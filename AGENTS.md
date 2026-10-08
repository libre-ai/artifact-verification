# artifact-verification Canonical Agent Rules

## Authority

Artifact integrity and content provenance, couche 3 brick of the
constellation: the Rust library `libre-ai-artifact` and the TypeScript package
`@libre-ai/provenance` (`packages/provenance`).
Doctrine lives upstream: https://raw.githubusercontent.com/libre-ai/project-governance/HEAD/AGENTS.md

## Boundaries

- Contract types are canonical in `libre-ai/schemas-and-contracts`
  (`crates/sdk-rs`, consumed as a sibling path), never redefined here.
- These libraries verify content against supplied evidence; they do not
  select trusted evidence or keys — that choice stays with the consumer.
- No storage, network or key custody responsibility is added here.

## Quality gates

Run `bun run check` from the local composition before pushing (it includes
`cargo coverage-check`); never hide a red test.

## Agents

- Security > quality > performance > completeness, in that order on conflict.
- Stage files before running tree-walking gates.
- Never put caller-supplied private key material in logs or errors.
- Never commit a machine-local absolute filesystem path.
