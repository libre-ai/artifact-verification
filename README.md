<!-- SPDX-FileCopyrightText: 2026 Libre AI contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Written for the retained Libre AI portfolio on 2026-09-14; earlier source documents and revisions retain their original licensing. -->

# Libre AI Artifact Verification

## Intended use

Help a consumer check whether exact artifact bytes match the declared manifest and the evidence bound to it. Verification should make a mismatch or missing proof explicit before the consumer relies on the artifact.

## Existing candidates and limits

Earlier sources include an in-memory artifact verifier and separate provenance material. Only content relevant to artifact verification belongs in this proposed boundary; historical contributor-lineage models are not automatically included. This documentary candidate admits no distributed verifier, signing service or complete supply-chain guarantee.

## Proposed contracts

A verification request identifies the artifact bytes, manifest and required evidence. A result states which bindings passed or failed and the limits of the check. A valid digest or signature does not grant permission to execute or publish the artifact. Contracts owns canonical formats; publication and execution retain their separate authorities.

## Activation criteria

Qualify an exact verifier and clean consumer against independent byte-level cases. Refuse tampered, missing, extra or ambiguously identified content and inconsistent evidence. Verify the selected trust rules where signatures are required, and distinguish content integrity from factual correctness of a claim. Review dependencies, rights and packaging without adding storage, network or signing responsibilities implicitly.

Qualification follows the actual selected scope. A candidate module may be admitted independently with its own consumer and evidence; complete journey criteria apply to the corresponding product or integration. A pure core does not require a worker, database or relay integration that is outside its scope. Neither module admission nor this repository’s documentary existence requires a complete Missions journey.

[Français](README.fr.md)

## Portfolio navigation

These links describe the intended retained portfolio. Public availability and reachability are not verified for this private candidate.

### Products

- [Libre AI Work Supervision](https://github.com/libre-ai/ai-work-supervision)
- [Libre AI Model Policy](https://github.com/libre-ai/ai-model-policy)
- [Libre AI Practice Workbench](https://github.com/libre-ai/ai-practice-workbench)
- [Libre AI Learning Session Facilitation](https://github.com/libre-ai/learning-session-facilitation)
- [Libre AI Personal Knowledge Notebook](https://github.com/libre-ai/personal-knowledge-notebook)
- [Libre AI Information Feed Filter](https://github.com/libre-ai/information-feed-filter)
- [Libre AI Travel Itinerary Planner](https://github.com/libre-ai/travel-itinerary-planner)
- [Libre AI Public Vote Comparison](https://github.com/libre-ai/public-vote-comparison)

### Components and tools

- [Libre AI Application Development Toolkit](https://github.com/libre-ai/application-development-toolkit)
- [Libre AI Schemas And Contracts](https://github.com/libre-ai/schemas-and-contracts)
- [Libre AI Collaborative Data Sync](https://github.com/libre-ai/collaborative-data-sync)
- [Libre AI Execution Continuity Evaluator](https://github.com/libre-ai/execution-continuity-evaluator)
- [Libre AI Execution Sandbox](https://github.com/libre-ai/execution-sandbox)
- [Libre AI Capability Authorization](https://github.com/libre-ai/capability-authorization)
- [Libre AI Organization Data Lifecycle](https://github.com/libre-ai/organization-data-lifecycle)
- [Libre AI Database Policy Inspector](https://github.com/libre-ai/database-policy-inspector)
- [Libre AI Artifact Verification](https://github.com/libre-ai/artifact-verification)

### Project

- [Libre AI](https://github.com/libre-ai/.github)
- [Libre AI Project Website](https://github.com/libre-ai/project-website)
- [Libre AI Project Governance](https://github.com/libre-ai/project-governance)



---

## Reviewed editorial source

[Reviewed material](https://github.com/libre-ai/artifact-verification/blob/beb3910464e7cbde75c2854689edafe03ef6c34b/docs/portfolio-material.json)

SHA-256: `ea7d6d78e06628d1e307e748a7e22b7ae9ceff7db5cfbafc182d07a034433973`
