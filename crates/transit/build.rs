// Build script: inject git SHA, build date, and Rust version as compile-time
// env vars so they can be embedded in the binary and exposed via /version.
//
// No cargo:rerun-if-changed is printed, so cargo re-runs this script on every
// build — correct behaviour for git SHA injection (we always want the HEAD at
// build time, not at some stale cached point).

fn main() {
    // Git commit SHA (short form).  Falls back to "unknown" when building
    // outside a git repository (e.g. release tarballs, Docker scratch builds).
    let git_sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_SHA={git_sha}");

    // Build timestamp in ISO 8601 UTC.
    let build_date = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BUILD_DATE={build_date}");

    // Rust toolchain version string (e.g. "rustc 1.78.0 (9b00956e5 2024-04-29)").
    let rust_version = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=RUST_VERSION_STR={rust_version}");
}
