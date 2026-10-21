//! Where each did:scid identity this community has verified was last found
//! (VTI-KEY-162).
//!
//! A did:scid identity is the bare `did:scid:vh:1:<scid>`; its `?src=` is only
//! a locator (VTI-KEY-160). Members, administrators and peers are recorded by
//! the bare DID, so after a restart the resolver could not resolve one again
//! until it next presented its `src`. Every proof this community verifies under
//! a did:scid DID URL with `src` records that source here, keyed by the bare
//! DID and overwritten when a newer one is presented; boot seeds the resolver's
//! did:scid source book from it.
//!
//! The rows live in the `members` keyspace under their own prefix, so they are
//! backed up with the members they locate. A source is a hint, never trust:
//! the resolver still verifies the log, and refuses one older than a version it
//! has seen for the SCID.

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

/// Clear of the `members:` and pseudonym prefixes the keyspace already holds.
const PREFIX: &str = "scid_source:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScidSource {
    /// The DID URL the identity was last verified through.
    did_url: String,
}

fn key(bare: &str) -> String {
    format!("{PREFIX}{bare}")
}

/// Record the source of a did:scid DID URL just verified. Returns whether a row
/// was written: `false` for anything but a did:scid with `src`, and for a
/// source already recorded.
pub async fn record(ks: &KeyspaceHandle, did_url: &str) -> Result<bool, AppError> {
    let did_url = did_url.split('#').next().unwrap_or(did_url);
    if !vta_sdk::did_scid::is_scid(did_url) || vta_sdk::did_scid::src(did_url).is_none() {
        return Ok(false);
    }
    let bare = vta_sdk::did_scid::identity(did_url);
    let current: Option<ScidSource> = ks.get(key(&bare)).await?;
    if current.as_ref().is_some_and(|c| c.did_url == did_url) {
        return Ok(false);
    }
    ks.insert(
        key(&bare),
        &ScidSource {
            did_url: did_url.to_string(),
        },
    )
    .await?;
    debug!(did = %bare, source = %did_url, "did:scid source recorded");
    Ok(true)
}

/// [`record`], logging rather than failing: a source not recorded costs a
/// re-presentation after a restart, never the request in hand.
pub async fn record_best_effort(ks: &KeyspaceHandle, did_url: &str) {
    if let Err(e) = record(ks, did_url).await {
        warn!(did = %did_url, error = %e, "did:scid source not recorded");
    }
}

/// The DID URL recorded for a did:scid identity, by its bare DID or any DID
/// URL of it.
pub async fn source_of(ks: &KeyspaceHandle, did: &str) -> Result<Option<String>, AppError> {
    let found: Option<ScidSource> = ks.get(key(&vta_sdk::did_scid::identity(did))).await?;
    Ok(found.map(|s| s.did_url))
}

/// Seed `resolver`'s did:scid sources from every recorded row, so a bare
/// did:scid this community verified before resolves after a restart. Returns
/// how many were seeded.
pub async fn seed(ks: &KeyspaceHandle, resolver: &DIDCacheClient) -> Result<usize, AppError> {
    let mut seeded = 0;
    for (_key, raw) in ks.prefix_iter_raw(PREFIX.as_bytes().to_vec()).await? {
        match serde_json::from_slice::<ScidSource>(&raw) {
            Ok(row) if resolver.scid_sources().add_source(&row.did_url) => seeded += 1,
            Ok(_) => {}
            Err(e) => warn!(error = %e, "unreadable did:scid source row skipped"),
        }
    }
    Ok(seeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_did_resolver_cache_sdk::{
        config::DIDCacheConfigBuilder, network_resolvers::HostPolicy,
    };
    use didwebvh_rs::prelude::*;
    use serde_json::json;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn open_ks() -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = vti_common::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(crate::store::keyspaces::MEMBERS).unwrap();
        (dir, ks)
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_host_policy(HostPolicy::AllowPrivate)
                .build(),
        )
        .await
        .unwrap()
    }

    /// A signed did:webvh log, listing its did:scid alias, served at the mock
    /// server's root; returns its did:scid DID URL.
    async fn serve_member(server: &MockServer) -> String {
        let port = server.address().port();
        let (_, key) = didwebvh_rs::did_key::generate_did_key(KeyType::Ed25519).unwrap();
        let pk = key.get_public_keymultibase().unwrap();
        let config = CreateDIDConfig::builder()
            .address(format!("http://localhost:{port}/"))
            .authorization_key(key)
            .did_document(json!({
                "id": "{DID}",
                "@context": ["https://www.w3.org/ns/did/v1"],
                "verificationMethod": [{ "id": "{DID}#key-0", "type": "Multikey",
                    "controller": "{DID}", "publicKeyMultibase": pk }],
                "authentication": ["{DID}#key-0"],
            }))
            .parameters(Parameters {
                update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
                ..Default::default()
            })
            .also_known_as_scid(true)
            .build()
            .unwrap();
        let created = create_did(config).await.unwrap();
        Mock::given(method("GET"))
            .and(path("/.well-known/did.jsonl"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(serde_json::to_string(created.log_entry()).unwrap()),
            )
            .mount(server)
            .await;
        vta_sdk::did_scid::scid_forms(created.did()).unwrap().1
    }

    /// VTI-KEY-162: a member verified through its `src` before a restart
    /// resolves by its bare DID after one, from the seeded source — and does not
    /// without it.
    #[tokio::test]
    async fn a_bare_member_did_resolves_after_a_restart() {
        let server = MockServer::start().await;
        let url = serve_member(&server).await;
        let bare = vta_sdk::did_scid::identity(&url);
        let (_dir, ks) = open_ks();

        // Before the restart: verified through its src, and recorded.
        resolver()
            .await
            .resolve(&url)
            .await
            .expect("resolves with src");
        assert!(record(&ks, &format!("{url}#key-0")).await.unwrap());

        // After: a fresh resolver knows no source until seeded.
        let cold = resolver().await;
        assert!(cold.resolve(&bare).await.is_err());

        let warm = resolver().await;
        assert_eq!(seed(&ks, &warm).await.unwrap(), 1);
        let doc = warm
            .resolve(&bare)
            .await
            .expect("bare DID resolves from the seed");
        assert_eq!(doc.doc.id.as_str(), bare);
    }

    #[tokio::test]
    async fn a_newer_source_replaces_the_recorded_one() {
        let (_dir, ks) = open_ks();
        let first = "did:scid:vh:1:QmScid?src=a.example/m";
        let moved = "did:scid:vh:1:QmScid?src=b.example/m";
        assert!(record(&ks, first).await.unwrap());
        assert!(
            !record(&ks, first).await.unwrap(),
            "unchanged: nothing written"
        );
        assert!(record(&ks, moved).await.unwrap());
        assert_eq!(
            source_of(&ks, "did:scid:vh:1:QmScid")
                .await
                .unwrap()
                .as_deref(),
            Some(moved)
        );
        for not_a_source in [
            "did:scid:vh:1:QmScid",
            "did:webvh:QmScid:a.example",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ] {
            assert!(!record(&ks, not_a_source).await.unwrap(), "{not_a_source}");
        }
        // Not a member row: a member listing never sees it.
        assert!(
            crate::members::storage::list_members(&ks)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
