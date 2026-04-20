#![no_main]

use libfuzzer_sys::fuzz_target;
use usenet_ipfs_core::{
    article::{Article, ArticleBody, ArticleHeader, GroupName},
    validation::{validate_article_ingress, ValidationConfig},
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

    // Build group list — accept whatever GroupName::new returns, skip invalids.
    let newsgroups: Vec<GroupName> = newsgroups_raw
        .split(',')
        .filter_map(|g| GroupName::new(g.trim()).ok())
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

    let config = ValidationConfig::default();

    // Must not panic. Return value (Ok/Err) is not checked — both are valid.
    let _ = validate_article_ingress(&article, &config);
});
