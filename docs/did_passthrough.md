# X-Usenet-IPFS-DID-Sig Header Passthrough

## What it is

The `X-Usenet-IPFS-DID-Sig` header carries a Decentralized Identifier (DID)
signature over the article content. Posters may include this header to
cryptographically attest to authorship using a DID key.

## v1 behavior: passthrough only

usenet-ipfs v1 does **not** resolve DIDs or verify DID signatures.
The header is stored and returned to readers unchanged.

Rationale: DID resolution requires network access to DID document endpoints,
which varies by DID method. Implementing full DID verification is deferred to
a future version.

## What readers see

Clients receive the `X-Usenet-IPFS-DID-Sig` header in ARTICLE and HEAD
responses exactly as posted. Clients that understand DID signatures can
perform their own verification.

## Security implications

Because v1 does not verify DID signatures, the presence of this header
provides no security guarantee from the server's perspective. The header
is informational only.
