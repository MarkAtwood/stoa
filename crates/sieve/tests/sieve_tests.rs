use usenet_ipfs_sieve::{compile, evaluate, SieveAction};

// Minimal RFC 5322 message with a given subject line.
// Headers are CRLF-terminated; blank line separates headers from body.
fn make_message(subject: &str) -> Vec<u8> {
    format!(
        "From: sender@example.com\r\n\
         To: recipient@example.com\r\n\
         Subject: {subject}\r\n\
         Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
         \r\n\
         Body text.\r\n"
    )
    .into_bytes()
}

fn is_keep(a: &SieveAction) -> bool {
    matches!(a, SieveAction::Keep)
}

fn is_discard(a: &SieveAction) -> bool {
    matches!(a, SieveAction::Discard)
}

fn is_fileinto(a: &SieveAction, folder: &str) -> bool {
    matches!(a, SieveAction::FileInto(f) if f == folder)
}

// Test 1: implicit keep — script has no action, RFC 5228 §4.1 mandates Keep.
#[test]
fn test_implicit_keep() {
    // Empty script — no require, no actions. RFC 5228 §4.1 implicit keep applies.
    let script = b"";
    let cs = compile(script).expect("valid script should compile");
    let msg = make_message("Hello");
    let actions = evaluate(&cs, &msg, "sender@example.com", "recipient@example.com");
    assert_eq!(actions.len(), 1, "expected exactly one action");
    assert!(is_keep(&actions[0]), "expected Keep action");
}

// Test 2: fileinto when subject contains "URGENT" (RFC 5228 §5.7.1 header + :contains).
// fileinto requires capability declaration per RFC 5228 §2.10.5.
#[test]
fn test_fileinto_subject_match() {
    let script = b"require [\"fileinto\"];\
                   if header :contains \"Subject\" \"URGENT\" { fileinto \"INBOX.Urgent\"; }";
    let cs = compile(script).expect("valid script should compile");
    let msg = make_message("URGENT task");
    let actions = evaluate(&cs, &msg, "sender@example.com", "recipient@example.com");
    assert_eq!(actions.len(), 1, "expected exactly one action");
    assert!(
        is_fileinto(&actions[0], "INBOX.Urgent"),
        "expected FileInto(\"INBOX.Urgent\")"
    );
}

// Test 3: discard when X-Spam-Flag: YES header is present (RFC 5228 §5.7.1 + §4.2 discard).
#[test]
fn test_discard_spam_header() {
    let script = b"if header :contains \"X-Spam-Flag\" \"YES\" { discard; }";
    let cs = compile(script).expect("valid script should compile");
    let msg = b"From: sender@example.com\r\n\
                To: recipient@example.com\r\n\
                Subject: Hello\r\n\
                Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
                X-Spam-Flag: YES\r\n\
                \r\n\
                Body text.\r\n";
    let actions = evaluate(&cs, msg, "sender@example.com", "recipient@example.com");
    assert_eq!(actions.len(), 1, "expected exactly one action");
    assert!(is_discard(&actions[0]), "expected Discard action");
}

// Test 4: implicit keep when condition is false — "URGENT" not in "Normal message".
#[test]
fn test_keep_when_condition_false() {
    let script = b"require [\"fileinto\"];\
                   if header :contains \"Subject\" \"URGENT\" { fileinto \"INBOX.Urgent\"; }";
    let cs = compile(script).expect("valid script should compile");
    let msg = make_message("Normal message");
    let actions = evaluate(&cs, &msg, "sender@example.com", "recipient@example.com");
    assert_eq!(actions.len(), 1, "expected exactly one action");
    assert!(is_keep(&actions[0]), "expected Keep action");
}

// Test 5: size :over test (RFC 5228 §5.9) — message is under 1000 bytes, so keep.
#[test]
fn test_size_over_not_triggered() {
    let script = b"require [\"fileinto\"];\
                   if size :over 1000 { fileinto \"INBOX.Large\"; }";
    let cs = compile(script).expect("valid script should compile");
    // Construct a short message well under 1000 bytes.
    let msg = b"From: sender@example.com\r\n\
                To: recipient@example.com\r\n\
                Subject: Small\r\n\
                Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
                \r\n\
                Short body.\r\n";
    assert!(
        msg.len() < 1000,
        "test message must be under 1000 bytes; actual len = {}",
        msg.len()
    );
    let actions = evaluate(&cs, msg, "sender@example.com", "recipient@example.com");
    assert_eq!(actions.len(), 1, "expected exactly one action");
    assert!(is_keep(&actions[0]), "expected Keep action");
}

// Test 6: compile() returns Err on syntactically invalid Sieve.
#[test]
fn test_compile_error_on_invalid_script() {
    let result = compile(b"invalid sieve script @@@@");
    assert!(result.is_err(), "invalid script should fail to compile");
}

// Test 7: variables extension (RFC 5229) — set + fileinto with variable expansion.
#[test]
fn test_variables_set_and_fileinto() {
    let script = b"require [\"variables\", \"fileinto\"];\
                   set \"folder\" \"INBOX.Work\";\
                   fileinto \"${folder}\";";
    let cs = compile(script).expect("valid script with variables extension should compile");
    let msg = make_message("Work item");
    let actions = evaluate(&cs, &msg, "sender@example.com", "recipient@example.com");
    assert_eq!(actions.len(), 1, "expected exactly one action");
    assert!(
        is_fileinto(&actions[0], "INBOX.Work"),
        "expected FileInto(\"INBOX.Work\")"
    );
}
