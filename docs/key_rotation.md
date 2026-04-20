# Operator Key Rotation

## Overview

Each transit node has an operator ed25519 keypair. The private key signs all
articles written by this node. Rotating the key:

1. Generates a new keypair
2. Publishes a rotation announcement article signed with the old key
3. Updates the config to use the new key

## Rotation Protocol

### Step 1: Generate a new keypair

```
transit keygen --output-dir /etc/usenet-ipfs/keys/new/
```

### Step 2: Publish rotation announcement

```
transit key-rotate \
  --old-key /etc/usenet-ipfs/keys/operator_key.pem \
  --new-key /etc/usenet-ipfs/keys/new/operator_key.pub.pem \
  --group usenet.ipfs.keyrotation
```

This publishes a signed article to the `usenet.ipfs.keyrotation` group
announcing the new key.

### Step 3: Update config

Change `operator_key_path` in `transit.toml` to point to the new private key.

### Step 4: Restart transit

The new key takes effect immediately on restart. Peers that have received the
rotation announcement will accept articles signed with the new key.

## Announcement Article Format

The announcement is a standard RFC 5322 article with these headers:

```
From: key-rotation@usenet.ipfs
Newsgroups: usenet.ipfs.keyrotation
Subject: Key rotation announcement
Message-ID: <rotate-{TIMESTAMP}@{NODE-ID}.usenet.ipfs>
X-Key-Rotation: new-key
X-Old-Key-Fingerprint: {SHA-256 of old public key SPKI DER, hex}
X-New-Key-Fingerprint: {SHA-256 of new public key SPKI DER, hex}
```

The body contains the new public key PEM block.

The article is signed with the OLD private key so peers can verify continuity
of identity.

## Security Notes

- Rotation announcements are stored in IPFS and replicated via gossipsub.
- Old key remains valid for articles received before the rotation propagates.
- Key rotation does NOT automatically revoke old articles.
- Keep a backup of the old private key for audit purposes.
- The private key is never logged or printed at any point in this workflow.
