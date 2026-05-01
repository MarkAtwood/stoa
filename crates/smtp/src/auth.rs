use std::net::IpAddr;

use mail_auth::{
    dmarc::{verify::DmarcParameters, Policy},
    spf::verify::SpfParameters,
    AuthenticatedMessage, AuthenticationResults, DmarcResult, MessageAuthenticator, Parameters,
};
use tracing::debug;

use crate::dns_cache::DnsCache;

/// The result of running the inbound authentication pipeline on one message.
#[derive(Debug)]
pub struct InboundAuthResult {
    /// Value for the `Authentication-Results:` header (the whole header value,
    /// not just the result token — includes the authserv-id prefix).
    pub header: String,
    /// `true` when DMARC policy is `reject`, SPF failed, and DKIM failed.
    /// The session should return 550 and not enqueue the message.
    pub dmarc_reject: bool,
}

/// Run the full inbound authentication pipeline:
/// DKIM → SPF (MAIL FROM) → DMARC → ARC.
///
/// Always returns an `InboundAuthResult`; errors from individual checks
/// produce `TempError` or `PermError` results in the header but never
/// propagate as Rust errors — RFC 7601 mandates that unverifiable checks
/// produce a result, not a rejection.
pub async fn verify_inbound(
    authenticator: &MessageAuthenticator,
    cache: &DnsCache,
    raw_message: &[u8],
    client_ip: IpAddr,
    ehlo_domain: &str,
    mail_from: &str,
    hostname: &str,
) -> InboundAuthResult {
    // Parse the message.  If it cannot be parsed at all we can still produce
    // a result (permerror) and continue — we will not reject.
    let Some(msg) = AuthenticatedMessage::parse(raw_message) else {
        return InboundAuthResult {
            header: format!("{hostname}; auth=permerror (message parse failed)"),
            dmarc_reject: false,
        };
    };

    // DKIM: verify all DKIM-Signature headers present in the message.
    let dkim_results = authenticator
        .verify_dkim(
            Parameters::new(&msg)
                .with_txt_cache(&cache.txt)
                .with_mx_cache(&cache.mx)
                .with_ipv4_cache(&cache.ipv4)
                .with_ipv6_cache(&cache.ipv6)
                .with_ptr_cache(&cache.ptr),
        )
        .await;

    // SPF: check MAIL FROM identity against the connecting IP.
    let spf_result = authenticator
        .verify_spf(
            Parameters::new(SpfParameters::verify_mail_from(
                client_ip,
                ehlo_domain,
                hostname,
                mail_from,
            ))
            .with_txt_cache(&cache.txt)
            .with_mx_cache(&cache.mx)
            .with_ipv4_cache(&cache.ipv4)
            .with_ipv6_cache(&cache.ipv6)
            .with_ptr_cache(&cache.ptr),
        )
        .await;

    // DMARC: check From: domain against SPF and DKIM results.
    let rfc5321_domain = mail_from
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or(ehlo_domain);
    let dmarc_result: mail_auth::DmarcOutput = authenticator
        .verify_dmarc(
            Parameters::new(DmarcParameters::new(
                &msg,
                &dkim_results,
                rfc5321_domain,
                &spf_result,
            ))
            .with_txt_cache(&cache.txt)
            .with_mx_cache(&cache.mx)
            .with_ipv4_cache(&cache.ipv4)
            .with_ipv6_cache(&cache.ipv6)
            .with_ptr_cache(&cache.ptr),
        )
        .await;

    // ARC: validate forwarded-mail chain for mailing lists.
    let arc_result = authenticator
        .verify_arc(
            Parameters::new(&msg)
                .with_txt_cache(&cache.txt)
                .with_mx_cache(&cache.mx)
                .with_ipv4_cache(&cache.ipv4)
                .with_ipv6_cache(&cache.ipv6)
                .with_ptr_cache(&cache.ptr),
        )
        .await;

    // Determine whether DMARC mandates rejection.
    // We only reject when policy=reject AND both SPF and DKIM fail — a passing
    // ARC chain in verify_arc is not yet considered here (v1 simplification;
    // a valid ARC chain should excuse DMARC failure for list mail, but that
    // requires policy-level ARC bypass logic added in a later epic).
    let dmarc_reject = matches!(dmarc_result.policy(), Policy::Reject)
        && matches!(dmarc_result.dkim_result(), DmarcResult::Fail(_))
        && matches!(dmarc_result.spf_result(), DmarcResult::Fail(_));

    // Build the Authentication-Results header value.
    let header_from = msg.from.first().map(String::as_str).unwrap_or("");
    let auth_header = AuthenticationResults::new(hostname)
        .with_dkim_results(&dkim_results, header_from)
        .with_spf_mailfrom_result(&spf_result, client_ip, mail_from, ehlo_domain)
        .with_dmarc_result(&dmarc_result)
        .with_arc_result(&arc_result, client_ip)
        .to_string();

    debug!(
        spf = ?spf_result.result(),
        dmarc_reject,
        "inbound auth complete"
    );

    InboundAuthResult {
        header: auth_header,
        dmarc_reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_cache::DnsCache;
    use std::net::Ipv4Addr;

    // Build a minimal RFC 5322 message with no DKIM signatures and a From
    // domain that has no DMARC record.  Under cargo test the mail-auth crate
    // uses mock_resolve() which returns DnsRecordNotFound for every lookup, so
    // all checks will produce None / TempError results — never reject.
    fn simple_message() -> Vec<u8> {
        b"From: sender@example.com\r\n\
          To: recipient@example.com\r\n\
          Subject: Hello\r\n\
          Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
          Message-ID: <test@example.com>\r\n\
          \r\n\
          Body text.\r\n"
            .to_vec()
    }

    fn make_auth() -> MessageAuthenticator {
        // `new_cloudflare()` creates a resolver pointing at 1.1.1.1, but
        // under `#[cfg(test)]` mail-auth's dns helpers call mock_resolve()
        // (returning NXDomain) before any real network I/O occurs.
        MessageAuthenticator::new_cloudflare().expect("resolver creation must not fail")
    }

    #[tokio::test]
    async fn plain_message_never_rejected() {
        let auth = make_auth();
        let cache = DnsCache::new();
        let msg = simple_message();
        let result = verify_inbound(
            &auth,
            &cache,
            &msg,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "client.example.com",
            "sender@example.com",
            "mx.example.com",
        )
        .await;

        assert!(
            !result.dmarc_reject,
            "plain message with no DMARC record must not be rejected"
        );
        // The Authentication-Results header value must start with the authserv-id.
        assert!(
            result.header.contains("mx.example.com"),
            "header must include authserv-id: {}",
            result.header
        );
    }

    #[tokio::test]
    async fn unparseable_message_returns_permerror() {
        let auth = make_auth();
        let cache = DnsCache::new();
        // A zero-length message cannot be parsed.
        let result = verify_inbound(
            &auth,
            &cache,
            b"",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "client.example.com",
            "sender@example.com",
            "mx.example.com",
        )
        .await;
        assert!(!result.dmarc_reject);
        assert!(
            result.header.contains("permerror"),
            "expected permerror in header: {}",
            result.header
        );
    }
}
