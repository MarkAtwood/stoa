"""Generate synthetic Usenet articles in mbox format.

Usage examples:

    # Generate 100 articles to stdout:
    python scripts/gen_articles.py --count 100 --group comp.lang.rust

    # Generate 10,000 articles to a file:
    python scripts/gen_articles.py --count 10000 --output /tmp/test_articles.mbox

    # Reproducible output with a fixed seed:
    python scripts/gen_articles.py --count 500 --seed 7 --output /tmp/out.mbox
"""

import argparse
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Word pool — built once, reused for all articles.
# Drawn from a fixed list so the output is deterministic given a seed.
# ---------------------------------------------------------------------------
_WORDS = (
    "the quick brown fox jumps over lazy dog rust programming language safe"
    " fast concurrent memory ownership borrow checker trait impl struct enum"
    " async await tokio network protocol message article usenet newsgroup"
    " server client transit reader ipfs content addressed block storage cid"
    " hash merkle dag cbor json canonical serialization signature verification"
    " peer gossip publish subscribe topic hierarchy filter ingress egress pin"
    " garbage collect retain expire index query result error propagate handle"
    " test vector oracle cross validate independent reference implementation"
    " binary crate library workspace manifest edition resolver feature flag"
    " integer float string slice vector hashmap btreemap option result box arc"
    " mutex channel spawn task future poll wake runtime executor thread pool"
    " socket bind listen accept connect read write flush shutdown timeout retry"
    " log trace debug info warn error span instrument metric counter gauge"
    " config environment variable argument parse validate default override"
    " schema type annotation derive macro attribute inline const static extern"
    " unsafe raw pointer alignment size_of transmute from_raw_parts slice_from"
    " cryptography ed25519 signature public private key seed entropy random"
    " nonce replay protect authenticate authorize identity certificate chain"
    " algorithm blake3 sha256 sha512 hmac kdf scrypt argon2 pbkdf2 aead gcm"
    " chacha20 poly1305 curve25519 ecdsa secp256k1 bip32 hd wallet mnemonic"
).split()


def _build_sentence(rng: random.Random, min_words: int = 6, max_words: int = 16) -> str:
    """Return a single capitalised sentence ending with a period."""
    n = rng.randint(min_words, max_words)
    words = [rng.choice(_WORDS) for _ in range(n)]
    words[0] = words[0].capitalize()
    return " ".join(words) + "."


def _build_paragraph(rng: random.Random) -> str:
    """Return 3–7 sentences joined by spaces."""
    n = rng.randint(3, 7)
    return " ".join(_build_sentence(rng) for _ in range(n))


def _build_body(rng: random.Random, min_bytes: int, max_bytes: int) -> str:
    """Return a body string whose UTF-8 length is between min_bytes and max_bytes."""
    target = rng.randint(min_bytes, max_bytes)
    parts: list[str] = []
    total = 0
    while total < target:
        para = _build_paragraph(rng)
        parts.append(para)
        total += len(para) + 2  # +2 for the trailing "\n\n"
    text = "\n\n".join(parts) + "\n"
    # Trim to max_bytes if we overshot (keep whole characters; ASCII-only pool).
    if len(text.encode()) > max_bytes:
        text = text.encode()[:max_bytes].decode(errors="ignore")
        if not text.endswith("\n"):
            text += "\n"
    return text


def _random_date(rng: random.Random, start: datetime, end: datetime) -> datetime:
    """Return a random datetime between start and end (UTC-aware)."""
    delta = int((end - start).total_seconds())
    offset = rng.randint(0, delta)
    return start + timedelta(seconds=offset)


def _rfc2822(dt: datetime) -> str:
    """Format a datetime as RFC 2822, e.g. 'Mon, 01 Jan 2024 00:00:00 +0000'."""
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _mbox_date(dt: datetime) -> str:
    """Format a datetime for the mbox 'From ' separator line."""
    return dt.strftime("%a %b %d %H:%M:%S %Y")


def generate_articles(
    count: int,
    group: str,
    min_size: int,
    max_size: int,
    start: datetime,
    end: datetime,
    seed: int,
) -> list[str]:
    """Return a list of mbox-formatted article strings (including 'From ' line)."""
    rng = random.Random(seed)
    articles: list[str] = []

    for n in range(1, count + 1):
        dt = _random_date(rng, start, end)
        msg_id = uuid.UUID(int=rng.getrandbits(128), version=4)
        author_n = rng.randint(1, max(1, count))
        body = _build_body(rng, min_size, max_size)

        header_lines = [
            f"From MAILER-DAEMON {_mbox_date(dt)}",
            f"From: synthetic-author-{author_n}@example.com",
            f"Date: {_rfc2822(dt)}",
            f"Message-ID: <gen-{msg_id}@example.com>",
            f"Newsgroups: {group}",
            f"Subject: Test article {n} of {count}",
            "Path: news.example.com!gen_articles",
            "",  # blank line between headers and body
        ]
        articles.append("\n".join(header_lines) + body)

    return articles


def _parse_date(s: str) -> datetime:
    """Parse YYYY-MM-DD into a UTC-aware datetime at midnight."""
    dt = datetime.strptime(s, "%Y-%m-%d")
    return dt.replace(tzinfo=timezone.utc)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic Usenet articles in mbox format.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--count", type=int, default=100, help="number of articles to generate")
    parser.add_argument("--group", default="comp.lang.rust", help="newsgroup name")
    parser.add_argument("--min-size", type=int, default=200, dest="min_size",
                        help="minimum article body size in bytes")
    parser.add_argument("--max-size", type=int, default=4096, dest="max_size",
                        help="maximum article body size in bytes")
    parser.add_argument("--start-date", default="2024-01-01", dest="start_date",
                        help="start date for generated articles (YYYY-MM-DD)")
    parser.add_argument("--end-date", default="2024-12-31", dest="end_date",
                        help="end date for generated articles (YYYY-MM-DD)")
    parser.add_argument("--output", default="-",
                        help="output file path; '-' writes to stdout")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducible output")
    args = parser.parse_args()

    if args.min_size < 1:
        parser.error("--min-size must be at least 1")
    if args.max_size < args.min_size:
        parser.error("--max-size must be >= --min-size")

    start = _parse_date(args.start_date)
    end = _parse_date(args.end_date)
    if end < start:
        parser.error("--end-date must be >= --start-date")

    articles = generate_articles(
        count=args.count,
        group=args.group,
        min_size=args.min_size,
        max_size=args.max_size,
        start=start,
        end=end,
        seed=args.seed,
    )

    # Join articles with a blank line between each, then a trailing newline.
    output = "\n\n".join(articles) + "\n"

    if args.output == "-":
        sys.stdout.write(output)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)


if __name__ == "__main__":
    main()
