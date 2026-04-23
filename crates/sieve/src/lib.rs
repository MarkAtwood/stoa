//! Sieve script evaluation for usenet-ipfs.
//!
//! # License note
//!
//! This crate depends on `sieve-rs`, which is licensed under **AGPL-3.0-only**.
//! Any binary that links this crate — including `usenet-ipfs-smtp` — is
//! therefore also governed by the AGPL-3.0.  Operators who run such a binary
//! as a network service are required by the AGPL to make the complete
//! corresponding source code available to the users of that service.
use std::sync::Arc;

use sieve::{Compiler, Envelope, Event, Input, Runtime};

/// A compiled Sieve script, ready for evaluation.
pub struct CompiledScript(Arc<sieve::Sieve>);

/// Disposition returned after evaluating a Sieve script against a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SieveAction {
    Keep,
    FileInto(String),
    Discard,
    Reject(String),
}

/// Compile a Sieve script from raw source bytes.
///
/// Returns `Err` with a human-readable description on parse or compile failure.
pub fn compile(script: &[u8]) -> Result<CompiledScript, String> {
    let compiler = Compiler::new();
    let sieve = compiler.compile(script).map_err(|e| format!("{e:?}"))?;
    Ok(CompiledScript(Arc::new(sieve)))
}

/// Evaluate a compiled Sieve script against a raw RFC 5322 message.
///
/// `envelope_from` and `envelope_to` are the SMTP envelope addresses.
/// Returns the list of actions the script requests; defaults to `[Keep]`
/// when the script produces no explicit disposition (RFC 5228 §2.10.2).
pub fn evaluate(
    script: &CompiledScript,
    raw_message: &[u8],
    envelope_from: &str,
    envelope_to: &str,
) -> Vec<SieveAction> {
    let runtime = Runtime::new();
    let mut context = runtime.filter(raw_message);
    context.set_envelope(Envelope::From, envelope_from);
    context.set_envelope(Envelope::To, envelope_to);

    let mut actions: Vec<SieveAction> = Vec::new();
    // has_terminal must be set true for any action that constitutes a final
    // disposition per RFC 5228 §4.1.  If it remains false after all events,
    // an implicit Keep is inserted (see the block after the loop).
    // Any new Action variant that constitutes a final disposition MUST set
    // has_terminal = true in the corresponding match arm below.
    let mut has_terminal = false;
    let mut input = Input::script("main", Arc::clone(&script.0));

    while let Some(result) = context.run(input) {
        input = match result {
            Ok(event) => match event {
                Event::Keep { .. } => {
                    actions.push(SieveAction::Keep);
                    has_terminal = true;
                    true.into()
                }
                Event::Discard => {
                    actions.push(SieveAction::Discard);
                    has_terminal = true;
                    true.into()
                }
                Event::Reject { reason, .. } => {
                    actions.push(SieveAction::Reject(reason));
                    has_terminal = true;
                    true.into()
                }
                Event::FileInto { folder, .. } => {
                    actions.push(SieveAction::FileInto(folder));
                    has_terminal = true;
                    true.into()
                }
                other => {
                    tracing::debug!("sieve: unhandled event {:?}", other);
                    true.into()
                }
            },
            Err(err) => {
                tracing::debug!("sieve: runtime error {:?}", err);
                true.into()
            }
        };
    }

    if !has_terminal {
        actions.push(SieveAction::Keep);
    }

    actions
}
