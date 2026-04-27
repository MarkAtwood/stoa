#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use stoa_core::{
    article::{Article, ArticleBody, ArticleHeader, GroupName},
    validation::{validate_article_ingress, ValidationConfig},
    wildmat::GroupFilter,
};

fuzz_target!(|data: &[u8]| {
    // Convert arbitrary bytes into article fields.
    // We use split points in the data to produce different field values.
    // The exact split does not matter — we just need to exercise all paths.
    let s = String::from_utf8_lossy(data);
    let parts: Vec<&str> = s.splitn(8, '\x00').collect();

    let from = parts.first().copied().unwrap_or("").to_string();
    let date = parts.get(1).copied().unwrap_or("").to_string();
    let message_id = parts.get(2).copied().unwrap_or("").to_string();
    let newsgroups_raw = parts.get(3).copied().unwrap_or("");
    let subject = parts.get(4).copied().unwrap_or("").to_string();
    let path = parts.get(5).copied().unwrap_or("").to_string();
    let body_str = parts.get(6).copied().unwrap_or("");

    // Pass raw group name strings directly to validate_article_ingress without
    // pre-filtering, so the validator's group name format check (step 4) and
    // allowed_groups filter (step 5) are both reachable from fuzz input.
    let newsgroups: Vec<GroupName> = newsgroups_raw
        .split(',')
        .map(|g| GroupName::new_unchecked(g.trim()))
        .collect();

    let article = Article {
        header: ArticleHeader {
            from,
            date,
            message_id,
            newsgroups,
            subject,
            path,
            extra_headers: vec![],
        },
        body: ArticleBody {
            bytes: body_str.as_bytes().to_vec(),
        },
    };

    // Use a non-None allowed_groups so that both error paths are reachable:
    // - InvalidGroupInNewsgroups from step 4 (invalid group name format)
    // - InvalidGroupInNewsgroups from step 5 (no group matched the filter)
    let config = ValidationConfig {
        allowed_groups: Some(Arc::new(
            GroupFilter::new(&["comp.lang.rust", "alt.test"]).unwrap(),
        )),
        ..ValidationConfig::default()
    };

    // Must not panic. Return value (Ok/Err) is not checked — both are valid.
    let _ = validate_article_ingress(&article, &config);
});
