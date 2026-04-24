// SPDX-License-Identifier: MIT
//! Cross-validation: run identical scripts through sieve-native and the
//! sieve-rs-backed usenet-ipfs-sieve oracle; assert outputs match.

use usenet_ipfs_sieve as oracle;
use usenet_ipfs_sieve_native as native;

fn to_native(action: &oracle::SieveAction) -> native::SieveAction {
    match action {
        oracle::SieveAction::Keep => native::SieveAction::Keep,
        oracle::SieveAction::Discard => native::SieveAction::Discard,
        oracle::SieveAction::FileInto(f) => native::SieveAction::FileInto(f.clone()),
        oracle::SieveAction::Reject(r) => native::SieveAction::Reject(r.clone()),
    }
}

/// Run a script + message through both impls; assert outputs match.
fn cross_check(script_src: &[u8], raw_msg: &[u8], env_from: &str, env_to: &str) {
    let native_result = {
        let compiled = native::compile(script_src).unwrap_or_else(|e| {
            panic!(
                "native compile failed: {e}\nscript: {}",
                String::from_utf8_lossy(script_src)
            )
        });
        native::evaluate(&compiled, raw_msg, env_from, env_to)
    };
    let oracle_result = {
        let compiled = oracle::compile(script_src).unwrap_or_else(|e| {
            panic!(
                "oracle compile failed: {e}\nscript: {}",
                String::from_utf8_lossy(script_src)
            )
        });
        oracle::evaluate(&compiled, raw_msg, env_from, env_to)
    };
    let oracle_native: Vec<native::SieveAction> = oracle_result.iter().map(to_native).collect();
    assert_eq!(
        native_result,
        oracle_native,
        "MISMATCH\nscript: {}\nnative:  {:?}\noracle:  {:?}",
        String::from_utf8_lossy(script_src),
        native_result,
        oracle_native,
    );
}

fn make_msg(subject: &str) -> Vec<u8> {
    format!(
        "From: sender@example.com\r\nTo: recip@example.com\r\nSubject: {subject}\r\n\r\nBody.\r\n"
    )
    .into_bytes()
}

#[test]
fn implicit_keep() {
    cross_check(b"", &make_msg("test"), "", "");
}

#[test]
fn explicit_keep() {
    cross_check(b"keep;", &make_msg("test"), "", "");
}

#[test]
fn fileinto_inbox() {
    cross_check(
        b"require [\"fileinto\"]; fileinto \"INBOX\";",
        &make_msg("test"),
        "",
        "",
    );
}

#[test]
fn fileinto_newsgroup() {
    cross_check(
        b"require [\"fileinto\"]; fileinto \"newsgroup:comp.lang.rust\";",
        &make_msg("test"),
        "",
        "",
    );
}

#[test]
fn reject_with_reason() {
    cross_check(
        b"require [\"reject\"]; reject \"no spam\";",
        &make_msg("test"),
        "",
        "",
    );
}

#[test]
fn discard_action() {
    cross_check(b"discard;", &make_msg("test"), "", "");
}

#[test]
fn header_contains_match() {
    let script = b"require [\"fileinto\"]; if header :contains \"Subject\" \"URGENT\" { fileinto \"INBOX.Urgent\"; }";
    cross_check(script, &make_msg("URGENT: fix this now"), "", "");
    cross_check(script, &make_msg("Normal message"), "", "");
}

#[test]
fn header_is_case_insensitive() {
    let script = b"require [\"fileinto\"]; if header :is \"subject\" \"case test\" { fileinto \"Matched\"; }";
    cross_check(script, &make_msg("case test"), "", "");
    cross_check(script, &make_msg("CASE TEST"), "", "");
    cross_check(script, &make_msg("other"), "", "");
}

#[test]
fn address_localpart_match() {
    let script = b"if address :is :localpart \"From\" \"spam\" { discard; }";
    let spam_msg = b"From: spam@example.com\r\nSubject: test\r\n\r\nBody\r\n";
    let ok_msg = b"From: user@example.com\r\nSubject: test\r\n\r\nBody\r\n";
    cross_check(script, spam_msg, "", "");
    cross_check(script, ok_msg, "", "");
}

#[test]
fn size_over() {
    let script = b"if size :over 10 { discard; }";
    let small = b"From: a@b.com\r\n\r\nhi\r\n";
    let big = make_msg("x".repeat(200).as_str());
    cross_check(script, small, "", "");
    cross_check(script, &big, "", "");
}

#[test]
fn allof_anyof() {
    let script = b"require [\"fileinto\"]; if anyof(header :contains \"Subject\" \"rust\", header :contains \"Subject\" \"cargo\") { fileinto \"tech\"; }";
    cross_check(script, &make_msg("cargo update"), "", "");
    cross_check(script, &make_msg("rust edition"), "", "");
    cross_check(script, &make_msg("unrelated"), "", "");
}

#[test]
fn variables_set_fileinto() {
    cross_check(
        b"require [\"variables\", \"fileinto\"]; set \"list\" \"comp.lang.rust\"; fileinto \"newsgroup:${list}\";",
        &make_msg("test"),
        "",
        "",
    );
}

#[test]
fn rfc5228_appendix_example() {
    // RFC 5228 §10.1 example: route based on header contains
    let script = b"require [\"fileinto\"];\nif header :contains \"Subject\" \"Sieve\" {\n    fileinto \"INBOX.sieve\";\n}";
    cross_check(script, &make_msg("Sieve is cool"), "", "");
    cross_check(script, &make_msg("Something else"), "", "");
}
