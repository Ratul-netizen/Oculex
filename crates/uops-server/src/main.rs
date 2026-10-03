//! The server.
//!
//! Everything below this file has tests; this file is the order those things happen in,
//! which is the part that cannot be unit-tested and the part an operator experiences.
//!
//! ```text
//!   read the environment          fail here, before anything is opened
//!   connect to PostgreSQL         fail here, saying which host
//!   connect to ClickHouse         fail here, saying which host
//!   bootstrap if empty            print the credential, once
//!   bind the port                 nothing is reachable before this line
//!   serve until told to stop      finish what was accepted
//! ```
//!
//! # Why it does not run migrations
//!
//! A server that migrates its own schema on boot is convenient exactly once. After that
//! it is N replicas racing to apply the same DDL on a rolling deploy, a rollback that
//! has become a data migration, and a schema change that happens at the least observable
//! moment in the deployment. Migrations are `scripts/db.sh migrate` and `uops-ch-migrate`
//! — steps a human or a pipeline runs, with output someone reads.
//!
//! What this does instead is check that both stores answer before it binds a port, and
//! say which one did not when they do not.
//!
//! # Why the port is bound last
//!
//! Between opening a listener and finishing bootstrap there would be a window in which
//! the API is reachable and the first administrator does not yet exist. Nothing terrible
//! is reachable through that window today — every route requires a session, and there
//! are no sessions — but "nothing terrible is reachable *today*" is a property of the
//! current route table rather than of the design. Binding last removes the window
//! instead of arguing about what is in it.

use uops_server::{config, firstrun, shutdown, web};

use std::net::SocketAddr;
use std::process::ExitCode;

use uops_api::AppState;
use uops_secrets::{KekRing, LocalVault, MemoryAccessLog, RustCryptoAead};
use uops_store_ch::{ChClient, ChStore, TelemetryStore};
use uops_store_pg::{PgSealedStore, PgStore};

use crate::config::Config;

/// What this binary's vault is made of. The same three parts the poller uses, so a
/// credential sealed here opens there.
type Vault = LocalVault<RustCryptoAead, PgSealedStore, MemoryAccessLog>;

#[tokio::main]
async fn main() -> ExitCode {
    // `uops-server rotate-kek` is the one subcommand: a procedure a person runs, not a
    // service — `docs/kek-rotation.md` §3.2. Anything else is the server.
    let outcome = if std::env::args().nth(1).as_deref() == Some("rotate-kek") {
        rotate_kek().await
    } else {
        run().await
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // One line, on stderr, saying what failed. Not a panic: a backtrace through
            // tokio's internals tells an operator nothing they can act on, and buries
            // the sentence that does.
            eprintln!("uops-server: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    println!("uops-server starting: {}", config.summary());

    let store = PgStore::connect(&config.postgres).await.map_err(|e| {
        // The URL is in the config summary above, already redacted. Repeating it here
        // unredacted is how a password ends up in a support ticket.
        format!("cannot reach PostgreSQL: {e}")
    })?;
    store
        .health()
        .await
        .map_err(|e| format!("PostgreSQL is reachable but not answering: {e}"))?;

    let telemetry = ChStore::new(ChClient::new(config.clickhouse.clone()));
    let ch = telemetry
        .health()
        .await
        .map_err(|e| format!("cannot reach ClickHouse: {e}"))?;
    println!("clickhouse {} ready", ch.version);

    firstrun::run(&store, &config.first_run).await?;

    // The vault, if this deployment configured a key. Built before the state so a bad
    // KEK — unreadable, malformed, or group-readable — fails here with a sentence rather
    // than on the first request to store a credential.
    let vault = if config.kek.is_some() {
        println!("credential storage enabled");
        report_key_usage(&config, &store).await?;
        Some(open_vault(&config, &store)?)
    } else {
        // Not a warning. A deployment that only wants the inventory is a supported one,
        // and the credential routes say so themselves with a 503 naming the variable.
        println!("no KEK configured: device credentials cannot be stored");
        None
    };

    // Cloned before the state takes ownership: the engine holds the same pools rather
    // than opening its own, which is what keeps a single `docker compose up` to one set
    // of connections.
    let store_for_alerts = store.clone();
    let telemetry_for_alerts = telemetry.clone();
    let store_for_discovery = store.clone();
    let store_for_self_monitor = store.clone();
    let telemetry_for_self_monitor = telemetry.clone();

    // First-party operational events are observed in one elected process and written to
    // the nominated platform resource. The advisory lock keeps replicas from duplicating
    // collector, lease, and runbook events.
    let self_monitor = tokio::spawn(uops_platform_events::run(
        store_for_self_monitor,
        telemetry_for_self_monitor,
        shutdown::signal(),
    ));

    let state = if config.secure_cookies {
        AppState::new(store, telemetry)
    } else {
        // Named to be visible in a diff, and announced to be visible in a log. A
        // deployment that has this on has it on for a reason someone can now find.
        eprintln!("warning: UOPS_INSECURE_COOKIES is set — cookies will not carry Secure");
        AppState::new(store, telemetry).allowing_insecure_cookies()
    };

    let state = match vault {
        Some(v) => state.with_vault(v),
        None => state,
    };

    let state = state
        .with_sso(open_sso(&config))
        .with_public_url(&config.public_url);

    // The alert engine, in this process. It reads the same two stores the API does and
    // writes alert state through the same repository, so there is nothing to keep in
    // step — and an installation that runs `docker compose up` gets alerting without
    // starting a second thing. `UOPS_ALERTS=off` is for the replicas that should not.
    let alerts = if config.alerts {
        let engine = uops_alert::Engine::new(store_for_alerts.clone(), telemetry_for_alerts);
        println!("alerts: evaluating every tenant's rules");
        Some(tokio::spawn(uops_alert::run(
            engine,
            store_for_alerts,
            shutdown::signal(),
        )))
    } else {
        println!("alerts: disabled by UOPS_ALERTS");
        None
    };

    // The discovery scheduler, in this process for the same reason the alert engine is:
    // an installation that starts one thing gets a product rather than a component. It
    // shares the pool and the shutdown signal, and it claims each job through migration
    // 0020's index — so a second replica with this on is safe, merely redundant.
    let discovery = if !config.discovery {
        println!("discovery: disabled by UOPS_DISCOVERY");
        None
    } else if config.kek.is_none() {
        // Not a failure to start. An installation with no KEK has no stored credentials,
        // so it has no discovery job that could run — but it will have created jobs in
        // the UI, so the reason is said out loud rather than left as silence.
        println!("discovery: no KEK configured, so scheduled sweeps cannot open credentials");
        None
    } else {
        let sweeper = uops_sweeper::Live::new(
            store_for_discovery.clone(),
            open_vault(&config, &store_for_discovery)?,
        );
        println!("discovery: running scheduled jobs when they are due");
        Some(tokio::spawn(uops_sweeper::run(
            store_for_discovery,
            sweeper,
            shutdown::signal(),
        )))
    };

    // One assembly, shared with the boot test — see `uops_server::application`. The
    // security headers come from there and not from here, so that a test can observe them.
    let web_root = web::root_from_env();
    let app = uops_server::application(state, web_root.as_deref())?;
    if let Some(root) = &web_root {
        println!("serving the web app from {}", root.display());
    }

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|e| format!("cannot bind {}: {e}", config.bind))?;
    // Not config.bind: with a port of 0 the kernel chose one, and the chosen one is
    // what someone needs to connect to.
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    println!("listening on http://{addr}");

    // with_connect_info, so the audit layer can fall back to the socket's peer address
    // when there is no X-Forwarded-For. Without it a directly exposed server records no
    // client address at all, and the audit log's ip column is uniformly empty.
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown::signal())
        .await
        .map_err(|e| format!("server stopped: {e}"))?;

    // Each of these is watching the same signal and is already unwinding. Waiting rather
    // than dropping the handle means a rule that was mid-evaluation finishes writing its
    // state — a phase recorded without the notification that belongs to it is the one
    // inconsistency this process can produce on the way out.
    wait_for("discovery: the scheduler", discovery).await;
    wait_for("alerts: the engine", alerts).await;
    wait_for("self-monitoring: the observer", Some(self_monitor)).await;

    println!("stopped cleanly");
    Ok(())
}

/// Wait for a background task to unwind, and say so if it panicked rather than returned.
///
/// Said out loud because the symptom otherwise is an installation that stopped doing one of
/// its jobs — alerting, sweeping, or watching itself — at a point nobody can identify.
async fn wait_for(what: &str, task: Option<tokio::task::JoinHandle<()>>) {
    if let Some(task) = task
        && let Err(e) = task.await
    {
        eprintln!("{what} stopped unexpectedly: {e}");
    }
}

/// The single sign-on runtime — M12 §2.2.
///
/// Always built, because a *public* client needs no key material and a deployment with
/// no identity provider configured never reaches it. The envelope is added when there is
/// a KEK, which is what a confidential client's secret is sealed under; without one the
/// configuration route says so in a sentence naming the variable, rather than storing a
/// secret in the clear.
fn open_sso(config: &Config) -> uops_api::sso::Sso {
    let base = uops_api::sso::Sso::new();
    match open_envelope(config) {
        Ok(envelope) => base.with_envelope(envelope),
        Err(why) => {
            if config.kek.is_some() {
                // A KEK was configured and could not be opened. Loud, because the symptom
                // otherwise is an SSO configuration screen that refuses a client secret on
                // a server that appears to have a key.
                eprintln!("sso: the key ring could not be opened: {why}");
            }
            base
        }
    }
}

/// The key ring every sealed value in this process is opened with: the active key and,
/// when `UOPS_KEK_RETIRED_DIR` is set, every retired one — `docs/kek-rotation.md`.
///
/// One function for both the vault and the SSO envelope. They used to build their rings
/// separately, from identical code, and a retired-key directory added to one and not the
/// other would have left SSO secrets unopenable mid-rotation while device credentials kept
/// working — the kind of half-failure nobody connects to its cause.
fn open_ring(config: &Config) -> Result<KekRing, String> {
    let id = uops_secrets::record::KeyId(config.kek_id.clone());
    let mut ring = match config.kek.as_ref() {
        Some(config::KekSource::File(path)) => KekRing::from_file(path, id),
        Some(config::KekSource::Env(name)) => KekRing::from_env(name, id),
        // Unreachable through any caller, all of which check first. A sentence rather
        // than a panic, because the thing it would crash is a server at boot.
        None => return Err("no KEK is configured".to_owned()),
    }
    .map_err(|e| format!("the key ring could not be opened: {e}"))?;

    if let Some(dir) = &config.kek_retired_dir {
        ring.load_retired_dir(dir)
            .map_err(|e| format!("the retired keys could not be loaded: {e}"))?;
    }
    Ok(ring)
}

/// One envelope, for org-level secrets — today, an `OpenID` Connect client secret.
///
/// A separate ring from the vault's, and for the reason `open_vault` already gives:
/// [`KekRing`] is deliberately not `Clone`, because cloning it would put a second copy
/// of the key material somewhere nothing zeroizes. Reading the file again at boot is the
/// cheaper half of that trade.
///
/// # Errors
///
/// When no KEK is configured, or it cannot be read. Both are ordinary: a deployment
/// without one simply cannot hold a confidential client's secret.
fn open_envelope(config: &Config) -> Result<uops_secrets::Envelope<RustCryptoAead>, String> {
    Ok(uops_secrets::Envelope::new(
        RustCryptoAead,
        open_ring(config)?,
    ))
}

/// One vault, built from the configured key ring.
///
/// Called once per thing that needs one rather than shared, because neither [`KekRing`]
/// nor [`LocalVault`] is `Clone` — deliberately, since cloning a ring would put a second
/// copy of the key material somewhere nothing zeroizes. Reading the file twice at boot is
/// the cheaper half of that trade.
///
/// # Errors
///
/// When the KEK cannot be read, is not 64 hex characters, or — on Unix — is in a file
/// other local accounts can read.
fn open_vault(config: &Config, store: &PgStore) -> Result<Vault, String> {
    let ring = open_ring(config)?;

    Ok(LocalVault::new(
        RustCryptoAead,
        PgSealedStore::new(store.clone()),
        MemoryAccessLog::new(),
        ring,
    ))
}

/// Which keys the sealed rows need, against which keys this process holds.
///
/// Printed at every start, because the mistake it catches is silent otherwise: rotate the
/// key, forget the old one, and every credential sealed under it fails with `UnknownKek`
/// one poll at a time while the server reports healthy. Here it is one line at boot, naming
/// the variable that fixes it — `docs/kek-rotation.md` §3.3. Returns the table so
/// `rotate-kek` can print it before and after.
async fn report_key_usage(
    config: &Config,
    store: &PgStore,
) -> Result<Vec<uops_store_pg::kek::KekUsage>, String> {
    let ring = open_ring(config)?;
    let usage = store
        .kek_usage()
        .await
        .map_err(|e| format!("could not count sealed rows per key: {e}"))?;

    for u in &usage {
        let id = uops_secrets::record::KeyId(u.kek_id.clone());
        let state = if &id == ring.active_id() {
            "active"
        } else if ring.holds(&id) {
            "retired — run `uops-server rotate-kek` to move these to the active key"
        } else {
            "MISSING — no key with this id is loaded, so these rows cannot be opened. \
             Put it in UOPS_KEK_RETIRED_DIR as <id>.hex"
        };
        println!(
            "  key {:<18} {:>6} {:<18} {state}",
            u.kek_id, u.rows, u.table
        );
    }
    if usage
        .iter()
        .any(|u| !ring.holds(&uops_secrets::record::KeyId(u.kek_id.clone())))
    {
        eprintln!(
            "warning: sealed rows reference a key this server does not hold; those \
             credentials and secrets will fail to open until it is supplied"
        );
    }
    Ok(usage)
}

/// `uops-server rotate-kek`: move every sealed row onto the active key.
///
/// Device credentials through the vault, SSO client secrets through the envelope — the
/// half nothing walked before. Neither touches ciphertext: each re-wraps a row's data key
/// under the active KEK, conditionally, so a secret replaced mid-run is reported as
/// superseded rather than destroyed. Prints the per-key table before and after, and exits
/// non-zero if anything failed, because "the rotation finished" and "the rotation
/// succeeded" are different claims and only the second permits deleting the old key.
async fn rotate_kek() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    if config.kek.is_none() {
        return Err(
            "no KEK is configured: set UOPS_KEK_FILE (or UOPS_KEK_HEX) and UOPS_KEK_ID".into(),
        );
    }
    let store = PgStore::connect(&config.postgres)
        .await
        .map_err(|e| format!("cannot reach PostgreSQL: {e}"))?;

    println!("rotate-kek: active key is {}", config.kek_id);
    println!("before:");
    report_key_usage(&config, &store).await?;

    // Device credentials. `rotate_kek` is synchronous over a blocking bridge, which wants a
    // multi-threaded runtime — this binary's.
    let vault = open_vault(&config, &store)?;
    let creds = vault
        .rotate_kek()
        .map_err(|e| format!("credential rotation stopped: {e}"))?;
    println!(
        "credentials: {} re-wrapped, {} already current, {} superseded, {} failed",
        creds.rewrapped, creds.already_current, creds.superseded, creds.failed
    );

    // SSO client secrets.
    let envelope = open_envelope(&config)?;
    let active = uops_secrets::record::KeyId(config.kek_id.clone());
    let (mut rewrapped, mut current, mut superseded, mut failed) = (0usize, 0usize, 0usize, 0usize);
    let secrets = store
        .sealed_provider_secrets()
        .await
        .map_err(|e| format!("could not read SSO secrets: {e}"))?;
    for (id, sealed) in secrets {
        if sealed.kek_id == active {
            current += 1;
            continue;
        }
        let Ok(new) = envelope.rewrap(&uops_api::sso::secret_context(id), &sealed) else {
            failed += 1;
            continue;
        };
        match store
            .replace_provider_wrapping(id, &sealed.wrapped_dek, &new)
            .await
        {
            Ok(true) => rewrapped += 1,
            Ok(false) => superseded += 1,
            Err(_) => failed += 1,
        }
    }
    println!(
        "sso secrets: {rewrapped} re-wrapped, {current} already current, {superseded} superseded, {failed} failed"
    );

    println!("after:");
    report_key_usage(&config, &store).await?;

    let total_failed = creds.failed + failed;
    if total_failed > 0 {
        return Err(format!(
            "{total_failed} row(s) could not be re-wrapped — do NOT delete any retired key; \
             the table above shows which key they are still on"
        )
        .into());
    }
    println!(
        "rotate-kek: done. A retired key may be deleted once the table above shows no row on it \
         — and remove it from wherever the key is backed up too."
    );
    Ok(())
}
