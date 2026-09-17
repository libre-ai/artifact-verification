<!-- SPDX-FileCopyrightText: 2026 Libre AI contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Verify an artifact before integration

Detect changed, missing or unexpected files and check that supplied evidence binds to the expected content.

- **Rust library `libre-ai-artifact`**: compares files against manifest sizes and digests; refuses inconsistent or missing evidence for releases.
- **TypeScript package `@libre-ai/provenance`**: signs and verifies contribution records using an Ed25519 key supplied by the caller.

## Try it

Code is undergoing local integration. Place `schemas-and-contracts` next to this repository, then run:

```sh
cargo test --locked
```

The [tested examples](tests/candidate_verification.rs) cover accepted and refused inputs. The TypeScript package lives in [`packages/provenance`](packages/provenance).

These libraries do not establish trust by themselves: the application must select trusted evidence and keys. No package has been published to a registry at this stage.

[Français](README.fr.md)
