//! What key rotation needs from the store: which keys the rows use, and a way to re-wrap
//! the SSO client secrets, which are not in the vault's table.
//!
//! `docs/kek-rotation.md`. The device-credential half of a rotation already exists —
//! `LocalVault::rotate_kek` over `PgSealedStore` — and this is the rest: the per-key count
//! an operator reads to know when an old key may be destroyed, and the identity-provider
//! secrets that `Envelope::rewrap` can re-wrap and nothing walked.
//!
//! Every statement here is deliberately cross-tenant, for the reason `list_all` gives: a
//! rotation that stopped at a tenant boundary would leave behind rows only the retired key
//! can open. None of it reads plaintext — a sealed value is opaque to this store.

use uops_core::Result;
use uops_secrets::SealedValue;
use uops_secrets::record::KeyId;

use crate::error::map;
use crate::store::PgStore;

/// How many sealed rows one key holds, in one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KekUsage {
    /// `credential` or `identity_provider`.
    pub table: &'static str,
    pub kek_id: String,
    pub rows: i64,
}

impl PgStore {
    /// Sealed rows per key, across both tables that hold them.
    ///
    /// Counts every credential row, revoked ones included, because `list_all` — what the
    /// vault's rotation walks — includes them too. A count that included rows the rotation
    /// skipped would never reach zero, and the old key could never be deleted.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn kek_usage(&self) -> Result<Vec<KekUsage>> {
        // tenant-exempt: every row in every tenant — see the module docs.
        let credentials = sqlx::query!(
            r#"
            SELECT kek_id, count(*) AS "rows!"
              FROM credential
             GROUP BY kek_id
             ORDER BY kek_id
            "#,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("credential", String::new(), e))?;

        // tenant-exempt: providers belong to an organization, and every one is counted.
        let providers = sqlx::query!(
            r#"
            SELECT kek_id AS "kek_id!", count(*) AS "rows!"
              FROM identity_provider
             WHERE kek_id IS NOT NULL
             GROUP BY kek_id
             ORDER BY kek_id
            "#,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("identity provider", String::new(), e))?;

        Ok(credentials
            .into_iter()
            .map(|r| KekUsage {
                table: "credential",
                kek_id: r.kek_id,
                rows: r.rows,
            })
            .chain(providers.into_iter().map(|r| KekUsage {
                table: "identity_provider",
                kek_id: r.kek_id,
                rows: r.rows,
            }))
            .collect())
    }

    /// Every identity provider that holds a sealed client secret, with that secret.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said, or a stored nonce that is not twelve bytes.
    pub async fn sealed_provider_secrets(&self) -> Result<Vec<(uuid::Uuid, SealedValue)>> {
        // tenant-exempt: every provider in every organization — see the module docs.
        let rows = sqlx::query!(
            r#"
            SELECT id,
                   kek_id      AS "kek_id!",
                   wrapped_dek AS "wrapped_dek!",
                   dek_nonce   AS "dek_nonce!",
                   ciphertext  AS "ciphertext!",
                   nonce       AS "nonce!",
                   backend_id  AS "backend_id!"
              FROM identity_provider
             WHERE kek_id IS NOT NULL
             ORDER BY id
            "#,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| map("identity provider", String::new(), e))?;

        rows.into_iter()
            .map(|r| {
                Ok((
                    r.id,
                    SealedValue {
                        kek_id: KeyId::new(r.kek_id),
                        wrapped_dek: r.wrapped_dek,
                        dek_nonce: nonce12(&r.dek_nonce, r.id)?,
                        ciphertext: r.ciphertext,
                        nonce: nonce12(&r.nonce, r.id)?,
                        backend_id: r.backend_id,
                    },
                ))
            })
            .collect()
    }

    /// Replace a provider secret's wrapping, but only if it still holds `expected`.
    ///
    /// The same contract as the vault's `replace_wrapping`, for the same reason: the new
    /// wrapping was computed from a data key unwrapped out of the row as it was read. If an
    /// administrator replaced the secret in between, that wrapping is for a key the row no
    /// longer contains, and writing it would destroy the new secret. Returns `false` for
    /// that case — superseded, not failed — and the next rotation finds the row on whatever
    /// key it now has.
    ///
    /// Only the wrapping changes. The ciphertext and its nonce are untouched, which is what
    /// makes a KEK rotation cheap.
    ///
    /// # Errors
    ///
    /// Whatever `PostgreSQL` said.
    pub async fn replace_provider_wrapping(
        &self,
        id: uuid::Uuid,
        expected_wrapped_dek: &[u8],
        rewrapped: &SealedValue,
    ) -> Result<bool> {
        // tenant-exempt: the row is named by its primary key, from the walk above.
        let done = sqlx::query!(
            r#"
            UPDATE identity_provider
               SET kek_id = $2, wrapped_dek = $3, dek_nonce = $4
             WHERE id = $1 AND wrapped_dek = $5
            "#,
            id,
            rewrapped.kek_id.as_str(),
            &rewrapped.wrapped_dek,
            &rewrapped.dek_nonce[..],
            expected_wrapped_dek,
        )
        .execute(self.pool())
        .await
        .map_err(|e| map("identity provider", id.to_string(), e))?;
        Ok(done.rows_affected() == 1)
    }
}

fn nonce12(bytes: &[u8], id: uuid::Uuid) -> Result<[u8; uops_secrets::NONCE_LEN]> {
    <[u8; uops_secrets::NONCE_LEN]>::try_from(bytes).map_err(|_| {
        uops_core::Error::Storage(format!(
            "identity provider {id}: a stored nonce is not 12 bytes"
        ))
    })
}
