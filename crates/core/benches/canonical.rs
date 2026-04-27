use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use stoa_core::article::{Article, ArticleHeader, GroupName};
use stoa_core::canonical::canonical_bytes;

fn make_article(n: usize) -> Article {
    Article {
        header: ArticleHeader {
            from: format!("author-{n}@example.com"),
            date: "Mon, 01 Jan 2024 00:00:00 +0000".to_string(),
            message_id: format!("<bench-{n:08}@example.com>"),
            newsgroups: vec![
                GroupName::new("comp.lang.rust").unwrap(),
                GroupName::new("comp.test").unwrap(),
            ],
            subject: format!("Benchmark article {n}"),
            path: "news.example.com".to_string(),
            extra_headers: vec![
                ("X-Custom".to_string(), format!("header-{n}")),
                ("References".to_string(), format!("<ref-{n}@example.com>")),
            ],
        },
        body: b"This is the body of the article. It contains several sentences of text \
             to make it a reasonable size for a typical news post.\r\n\
             \r\n\
             Best regards,\r\nThe Author\r\n"
            .to_vec(),
    }
}

fn make_article_with_body_size(target_size: usize) -> Article {
    Article {
        header: ArticleHeader {
            from: "author@example.com".to_string(),
            date: "Mon, 01 Jan 2024 00:00:00 +0000".to_string(),
            message_id: "<bench-body-size@example.com>".to_string(),
            newsgroups: vec![
                GroupName::new("comp.lang.rust").unwrap(),
                GroupName::new("comp.test").unwrap(),
            ],
            subject: "Benchmark article body size".to_string(),
            path: "news.example.com".to_string(),
            extra_headers: vec![
                ("X-Custom".to_string(), "header-value".to_string()),
                ("References".to_string(), "<ref@example.com>".to_string()),
            ],
        },
        body: b"x".repeat(target_size),
    }
}

fn bench_canonicalize_single(c: &mut Criterion) {
    let article = make_article(1);
    c.bench_function("canonicalize_single", |b| {
        b.iter(|| canonical_bytes(black_box(&article)))
    });
}

fn bench_canonicalize_1000(c: &mut Criterion) {
    let articles: Vec<_> = (0..1000).map(make_article).collect();
    c.bench_function("canonicalize_1000", |b| {
        b.iter(|| {
            for article in &articles {
                let _ = canonical_bytes(black_box(article));
            }
        })
    });
}

fn bench_canonicalize_by_header_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonicalize_extra_headers");
    for n_extra in [0usize, 5, 20, 50] {
        let mut article = make_article(1);
        article.header.extra_headers = (0..n_extra)
            .map(|i| (format!("X-Extra-{i}"), format!("value-{i}")))
            .collect();
        group.bench_with_input(BenchmarkId::from_parameter(n_extra), &article, |b, a| {
            b.iter(|| canonical_bytes(black_box(a)))
        });
    }
    group.finish();
}

fn bench_canonicalize_by_body_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonicalize_by_body_size");
    for size in [100usize, 1024, 10240] {
        let article = make_article_with_body_size(size);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &article, |b, a| {
            b.iter(|| canonical_bytes(black_box(a)))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_canonicalize_single,
    bench_canonicalize_1000,
    bench_canonicalize_by_header_count,
    bench_canonicalize_by_body_size,
);
criterion_main!(benches);
