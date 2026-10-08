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

## Project status

<!-- libre-ai:project-status:begin -->
<!-- Section générée depuis project.v1.yaml — ne pas éditer à la main. -->

- Situation actuelle : Recovered source snapshot 388d032367060c0905c791997bd0efc61b2a85a9 is present. Product tests and CI were not rerun for this documentary integration; historical evidence is not qualification of this tree. No product admission or authority transfer is established. Historical responsibilities are not transferred here; the short-name repository that held them has been retired.
- Maturité : idea
- Exposition : idea
- Confiance : medium
- Preuves vérifiées le : 2026-10-07
- Avancement : Avancement non calculable — périmètre à clarifier

<!-- libre-ai:project-status:end -->

[Français](README.fr.md)
