//! Rotating the key-encryption key, end to end, through the binary an operator runs.
//!
//! `docs/kek-rotation.md`. Rotation was implemented and tested in pieces — the vault's
//! `rotate_kek`, the envelope's `rewrap` — and no operator could reach any of it. This test
//! is the procedure in §4 of that document, run against a real database and the real
//! `uops-server rotate-kek`: seal under the old key, move it to the retired directory, start
//! a new key, rotate, and then **open every row with only the new key in the ring**. That
//! last step is the whole claim. A rotation that reported success and left one row on the
//! old key would pass every check except this one.
//!
//! Driven through the binary (`CARGO_BIN_EXE_uops-server`) rather than the functions, so
//! the configuration — `UOPS_KEK_RETIRED_DIR`, the file names that become key ids — is
//! under test too. That is where the operator's mistakes would be.

use std::path::{Path, PathBuf};
use std::process::Command;

use uops_core::{AuthProtocol, CredentialMaterial, OrgId, PrivProtocol, Secret, TenantId};
use uops_secrets::record::KeyId;
use uops_secrets::{AccessContext, CredentialMeta, Envelope, KekRing, LocalVault, RustCryptoAead};
use uops_store_pg::{Config as PgConfig, PgSealedStore, PgStore};

const OLD_KEY: &str = "0303030303030303030303030303030303030303030303030303030303030303";
const NEW_KEY: &str = "0404040404040404040404040404040404040404040404040404040404040404";

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://uops:uops@localhost:5432/uops".into())
}

/// A database of its own: rotation walks every row in every tenant, and the shared test
/// database holds other tests' credentials under other keys.
struct Scratch {
    store: PgStore,
    name: String,
    url: String,
}

impl Scratch {
    async fn new() -> Self {
        let admin = PgStore::connect(&PgConfig {
            url: admin_url(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to admin database");
        let name = format!("uops_rotate_{}", OrgId::new().into_uuid().simple());
        sqlx::query(&format!(r#"CREATE DATABASE "{name}""#))
            .execute(admin.pool())
            .await
            .expect("create scratch database");
        let base = admin_url()
            .rsplit_once('/')
            .expect("url has a path")
            .0
            .to_owned();
        let url = format!("{base}/{name}");
        let store = PgStore::connect(&PgConfig {
            url: url.clone(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to scratch database");
        sqlx::migrate!("../../migrations")
            .run(store.pool())
            .await
            .expect("migrate scratch database");
        Self { store, name, url }
    }

    async fn drop_database(self) {
        let Self { store, name, .. } = self;
        store.pool().close().await;
        let admin = PgStore::connect(&PgConfig {
            url: admin_url(),
            ..PgConfig::default()
        })
        .await
        .expect("connect to admin database");
        sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{name}" WITH (FORCE)"#))
            .execute(admin.pool())
            .await
            .expect("drop scratch database");
    }
}

/// A key file, readable only by its owner — `KekRing::from_file` refuses anything else.
fn write_key(path: &Path, hex: &str) {
    std::fs::write(path, hex).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

fn keys_dir() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("uops-rotate-{}", OrgId::new().into_uuid().simple()));
    std::fs::create_dir_all(dir.join("retired")).expect("keys dir");
    dir
}

fn ring(path: &Path, id: &str) -> KekRing {
    KekRing::from_file(path, KeyId::new(id)).expect("ring")
}

type Vault = LocalVault<RustCryptoAead, PgSealedStore, uops_secrets::MemoryAccessLog>;

fn vault(store: &PgStore, ring: KekRing) -> Vault {
    LocalVault::new(
        RustCryptoAead,
        PgSealedStore::new(store.clone()),
        uops_secrets::MemoryAccessLog::new(),
        ring,
    )
}

fn snmpv3() -> Secret<CredentialMaterial> {
    Secret::new(CredentialMaterial::SnmpV3 {
        username: "netops".into(),
        auth: AuthProtocol::Sha256,
        auth_key: "auth-key-before-rotation".into(),
        privacy: PrivProtocol::Aes256,
        priv_key: "priv-key-before-rotation".into(),
    })
}

fn ctx() -> AccessContext {
    AccessContext::new(uops_core::scope::Actor::Collector, "rotation-test")
}

async fn org_and_tenant(store: &PgStore) -> (OrgId, TenantId) {
    let org = OrgId::new();
    let tenant = TenantId::new();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org.into_uuid())
        .bind("rotation-org")
        .execute(store.pool())
        .await
        .expect("organization");
    sqlx::query("INSERT INTO tenant (id, org_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(tenant.into_uuid())
        .bind(org.into_uuid())
        .bind("rotation")
        .bind("rotation")
        .execute(store.pool())
        .await
        .expect("tenant");
    (org, tenant)
}

fn rotate(scratch: &Scratch, keys: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_uops-server"))
        .arg("rotate-kek")
        .env("DATABASE_URL", &scratch.url)
        .env("UOPS_KEK_FILE", keys.join("kek.hex"))
        .env("UOPS_KEK_ID", "kek-2026-10")
        .env("UOPS_KEK_RETIRED_DIR", keys.join("retired"))
        .env_remove("UOPS_KEK_HEX")
        .output()
        .expect("run uops-server rotate-kek")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_rotation_every_row_opens_with_only_the_new_key() {
    let scratch = Scratch::new().await;
    let store = &scratch.store;
    let keys = keys_dir();
    let (org, tenant) = org_and_tenant(store).await;

    // ---- before: everything sealed under the old key, as every installation is today ----
    write_key(&keys.join("old.hex"), OLD_KEY);
    let credential = vault(store, ring(&keys.join("old.hex"), "default"))
        .put(tenant, snmpv3(), &CredentialMeta::new("core-switches"))
        .expect("seal a device credential under the old key");

    let provider = OrgId::new().into_uuid();
    let sealed = Envelope::new(RustCryptoAead, ring(&keys.join("old.hex"), "default"))
        .seal(
            &uops_api::sso::secret_context(provider),
            Secret::new("sso-client-secret".to_owned()),
        )
        .expect("seal an SSO secret under the old key");
    store
        .create_provider_with_id(
            provider,
            org,
            "Corporate IdP",
            "https://idp.example.invalid",
            "oculex",
            "groups",
            Some(&sealed),
        )
        .await
        .expect("provider");

    // ---- the procedure: old key into retired/, a new active key ----------------------
    std::fs::rename(
        keys.join("old.hex"),
        keys.join("retired").join("default.hex"),
    )
    .expect("retire the old key");
    write_key(&keys.join("kek.hex"), NEW_KEY);

    // The control. With only the new key nothing opens yet — so the success below is the
    // rotation's doing, and not a test that would pass whatever the binary did.
    let new_only = || ring(&keys.join("kek.hex"), "kek-2026-10");
    assert!(
        vault(store, new_only())
            .get(tenant, credential, &ctx())
            .is_err(),
        "the new key alone opened a credential sealed under the old one before any rotation"
    );

    let out = rotate(&scratch, &keys);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rotate-kek failed\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("credentials: 1 re-wrapped")
            && stdout.contains("sso secrets: 1 re-wrapped"),
        "both kinds of sealed row should have been re-wrapped:\n{stdout}"
    );

    // ---- the claim: the old key can now be destroyed --------------------------------
    std::fs::remove_file(keys.join("retired").join("default.hex")).expect("delete the old key");

    let opened = vault(store, new_only())
        .get(tenant, credential, &ctx())
        .expect("the device credential opens with only the new key");
    match opened.expose() {
        CredentialMaterial::SnmpV3 { auth_key, .. } => {
            assert_eq!(auth_key, "auth-key-before-rotation");
        }
        other => panic!("a different credential came back: {other:?}"),
    }

    let stored = store
        .provider_secret(provider)
        .await
        .expect("read")
        .expect("the provider still has a secret");
    assert_eq!(stored.kek_id.as_str(), "kek-2026-10");
    let secret = Envelope::new(RustCryptoAead, new_only())
        .open(&uops_api::sso::secret_context(provider), &stored)
        .expect("the SSO secret opens with only the new key");
    assert_eq!(secret.expose(), "sso-client-secret");

    // ---- and running it again changes nothing ---------------------------------------
    std::fs::write(
        keys.join("retired").join("README.md"),
        "empty: the rotation finished",
    )
    .ok();
    let again = rotate(&scratch, &keys);
    let again_out = String::from_utf8_lossy(&again.stdout);
    assert!(
        again.status.success(),
        "a second rotation failed:\n{again_out}"
    );
    assert!(
        again_out.contains("credentials: 0 re-wrapped, 1 already current")
            && again_out.contains("sso secrets: 0 re-wrapped, 1 already current"),
        "a second rotation should find everything already on the active key:\n{again_out}"
    );

    let _ = std::fs::remove_dir_all(&keys);
    scratch.drop_database().await;
}
