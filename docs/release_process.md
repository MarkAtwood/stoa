# Release Process

This document covers the versioning policy, changelog format, and release workflow for usenet-ipfs.

## 1. Versioning Policy

This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

All crates (`usenet-ipfs-core`, `usenet-ipfs-transit`, `usenet-ipfs-reader`) are workspace-versioned: they share a single version number declared in the workspace `Cargo.toml` and inherited by each crate. A release bumps all crates together.

### Version bump triggers

| Bump | Triggers |
|------|----------|
| **Major** | Breaking protocol changes: NNTP extension wire changes incompatible with existing clients, CID scheme or codec changes (DAG-CBOR codec 0x71 is pinned — changes here break stored data), gossipsub wire format changes that require peer coordination |
| **Minor** | New features: new RFC 3977 commands or extensions, new gossipsub topic namespaces, new operator CLI commands, new Prometheus metrics, additive schema fields |
| **Patch** | Bug fixes, security fixes, dependency updates, documentation updates |

### Pre-release labels

Pre-releases use hyphen suffixes in this order:

```
0.1.0-alpha.1   # early, incomplete, API unstable
0.1.0-beta.1    # feature-complete, stabilizing API
0.1.0-rc.1      # release candidate, no planned changes
0.1.0           # final release
```

The project is currently pre-alpha (`0.1.0`). No crates.io publication until the project reaches production-ready status.

## 2. CHANGELOG.md Format

The changelog lives at `CHANGELOG.md` in the workspace root and follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The changelog is **manually maintained**. Conventional commits enforce message format for machine tooling, but changelog entries require context — what user-visible behavior changed, why, and what the impact is — that commit subjects cannot carry.

### Section structure per release

```
## [X.Y.Z] - YYYY-MM-DD

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security
```

Omit empty sections. The `[Unreleased]` block at the top accumulates entries during development; it is converted to a versioned block at release time.

### Entry format

```
- Brief description of the user-visible change ([#NNN](https://github.com/MarkAtwood/usenet-ipfs/issues/NNN)) [@author]
```

Rules:
- One sentence, present tense, imperative mood ("Add X", not "Added X" or "Adds X")
- Issue or PR number is required when one exists
- Author handle is optional but encouraged for external contributors
- Do not include commit hashes; link the issue or PR instead

## 3. Release Workflow

These steps must be performed in order. Do not skip steps.

```
1.  Ensure the working tree is clean and on main:
        git checkout main && git pull --rebase

2.  Run the full test suite and linters:
        cargo test --workspace
        cargo clippy --workspace --all-features -- -D warnings
        cargo fmt --all --check

3.  Update CHANGELOG.md:
    - Rename [Unreleased] to [X.Y.Z] - YYYY-MM-DD (today's date)
    - Add a new empty [Unreleased] section at the top
    - Update the comparison link at the bottom:
        [Unreleased]: https://github.com/MarkAtwood/usenet-ipfs/compare/vX.Y.Z...HEAD
        [X.Y.Z]: https://github.com/MarkAtwood/usenet-ipfs/compare/vX.Y.(Z-1)...vX.Y.Z

4.  Extract the release notes for this version to a temp file:
        # copy the [X.Y.Z] section body to CHANGELOG_LATEST.md (not committed)

5.  Bump the version in the workspace Cargo.toml:
        # Edit [workspace.package] version = "X.Y.Z"
        # Verify: cargo metadata --no-deps --format-version 1 | jq '.workspace_members'

6.  Commit the version bump and changelog update:
        git add Cargo.toml CHANGELOG.md
        git commit -m "chore: release vX.Y.Z"

7.  Tag the release:
        git tag -a vX.Y.Z -m "Release vX.Y.Z"

8.  Push branch and tag:
        git push
        git push --tags

9.  Create the GitHub release:
        gh release create vX.Y.Z \
          --title "vX.Y.Z" \
          --notes-file CHANGELOG_LATEST.md

10. Publish to crates.io (deferred until production-ready):
        cargo publish -p usenet-ipfs-core
        # Wait for core to appear in the registry index before publishing dependents
        cargo publish -p usenet-ipfs-transit
        cargo publish -p usenet-ipfs-reader
```

Step 10 is blocked until the project exits pre-alpha. Do not publish to crates.io before that milestone is reached and explicitly approved.

## 4. Hotfix Process

A hotfix applies a critical bug or security fix to a released version without picking up unreleased development work from main.

```
1.  Branch from the release tag:
        git checkout -b hotfix/vX.Y.(Z+1) vX.Y.Z

2.  Apply the minimal fix. Do not bundle unrelated changes.

3.  Run the full test suite on the hotfix branch.

4.  Bump the patch version in Cargo.toml to X.Y.(Z+1).

5.  Update CHANGELOG.md on the hotfix branch.

6.  Commit:
        git add Cargo.toml CHANGELOG.md <changed files>
        git commit -m "fix: <brief description>"

7.  Tag and push:
        git tag -a vX.Y.(Z+1) -m "Release vX.Y.(Z+1)"
        git push origin hotfix/vX.Y.(Z+1) --tags

8.  Create the GitHub release (same as step 9 above).

9.  Cherry-pick the fix commit onto main if it applies cleanly:
        git checkout main
        git cherry-pick <commit-sha>
        git push

10. Delete the hotfix branch after the cherry-pick is confirmed:
        git push origin --delete hotfix/vX.Y.(Z+1)
```

## 5. Commit Message Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

| Prefix | Version implication |
|--------|---------------------|
| `feat:` | Minor bump candidate |
| `fix:` | Patch bump candidate |
| `feat!:` or `BREAKING CHANGE:` footer | Major bump |
| `chore:`, `docs:`, `test:`, `refactor:`, `perf:` | No bump required |

The commit message body may explain rationale, but the subject line must be self-contained and under 50 characters.

**Do not include Claude attribution, "Generated with", or similar AI tool footers in any commit message.** Commit messages must represent the author of record, not the tool used to assist.
