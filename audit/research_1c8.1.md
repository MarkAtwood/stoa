# Research Report: 1c8.1 CredentialStore Extraction

## Source File
- crates/reader/src/store/credentials.rs (233 lines)

## Public API
- CredentialStore { entries: HashMap<String,String> }
- from_credentials(users: &[UserCredential]) -> Self
- empty() -> Self
- from_file(path: &str) -> Result<Self, String>
- merge_from_file(&mut self, path: &str) -> Result<(), String>
- check(&self, username: &str, password: &str) -> bool (async)

## UserCredential locations
- reader/src/config.rs:50 (canonical, has credential_file)
- mail/src/config.rs:47 (duplicate, no credential_file)

## Call sites
- reader/src/store/server_stores.rs: imports + uses build_credential_store
- reader/src/session/lifecycle.rs:256: check() call
- reader/tests/e2e_data_flow.rs: from_credentials()
- crates/integration-tests: empty() calls

## New crate layout
- crates/auth/ (new, MIT license)
- deps: bcrypt="0.15", tokio="1" (spawn_blocking), serde="1" derive
- dev-deps: tempfile="3"
