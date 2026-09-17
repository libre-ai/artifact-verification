import { createHash, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

/**
 * Provenance brick (couche 3) — AgentContributorLineage v1 (BOT-C).
 *
 * Records who contributed to a subject (agents + roles + per-contribution
 * digests) and signs a canonical digest of the record with **Ed25519**:
 * asymmetric origin authentication (unlike the envelope's symmetric HMAC —
 * anyone with the public key verifies, only the signing-key holder produces).
 * The digest is length-prefixed so no field boundary can be shifted by
 * content. Fails closed on any tamper or wrong key.
 *
 * The production signing key is an owner key ceremony (deferred, WP-G2-Z01 /
 * decision P3) — this brick takes the key as a parameter; dev keys drive tests.
 */

export const LINEAGE_SCHEMA_VERSION = "libre-ai.agent-contributor-lineage.v1" as const;

const ROLES = ["author", "executor", "fixer", "editor"] as const;
export type ContributorRole = (typeof ROLES)[number];

const SHA256 = /^[a-f0-9]{64}$/;

/**
 * Cardinality bounds of `agent-contributor-lineage.v1` (schema held by the
 * `contracts` repository). The brick enforces them itself so that neither end
 * depends on a consumer running schema validation.
 */
const MAX_CONTRIBUTORS = 64;
const MAX_OBSERVATIONS = 1000;

export interface ContributorInput {
  readonly agentId: string;
  readonly roles: readonly ContributorRole[];
  readonly contributionDigest: string;
}

export interface ObservationRef {
  readonly id: string;
  readonly digest: string;
  readonly mediaType: string;
}

export interface LineageInput {
  readonly id: string;
  readonly tenantId: string;
  readonly missionId: string;
  readonly subjectDigest: string;
  readonly contributors: readonly ContributorInput[];
  readonly observations: readonly ObservationRef[];
  readonly generatedAt: string;
}

export interface Contributor {
  readonly agentId: string;
  readonly roles: readonly ContributorRole[];
  readonly contributionDigest: string;
}

export interface AgentContributorLineage {
  readonly schemaVersion: typeof LINEAGE_SCHEMA_VERSION;
  readonly id: string;
  readonly tenantId: string;
  readonly missionId: string;
  readonly subjectDigest: string;
  readonly contributors: readonly Contributor[];
  readonly observations: readonly ObservationRef[];
  readonly generatedAt: string;
  readonly signingKeyId: string;
  readonly lineageDigest: string;
  readonly signature: string;
}

export interface SigningKey {
  readonly id: string;
  readonly privateKey: KeyObject;
}

export interface VerifyKey {
  readonly id: string;
  readonly publicKey: KeyObject;
}

export class LineageIntegrityError extends Error {
  constructor() {
    super("lineage integrity verification failed");
    this.name = "LineageIntegrityError";
  }
}

const encoder = new TextEncoder();

function assertDigest(value: string, what: string): void {
  if (!SHA256.test(value)) {
    throw new RangeError(`${what} must be an opaque SHA-256 digest`);
  }
}

function hasDuplicates(keys: readonly string[]): boolean {
  return new Set(keys).size !== keys.length;
}

// `uniqueItems` compares JSON values, so a positional JSON key reproduces that
// semantics exactly — including on the untrusted path, where a field is free to
// contain whatever byte a delimiter convention would have relied on.
function contributorKey(contributor: Contributor): string {
  return JSON.stringify([contributor.agentId, contributor.roles, contributor.contributionDigest]);
}

function observationKey(observation: ObservationRef): string {
  return JSON.stringify([observation.id, observation.digest, observation.mediaType]);
}

/**
 * The cardinality rules of `agent-contributor-lineage.v1`, stated once and
 * applied to both ends of the brick: what it agrees to sign, and what it agrees
 * to call verified. A rule enforced only at build time protects nothing — the
 * verifier is the one that lends a record authority, and it accepts records
 * this brick never produced (an earlier version of it, another implementation
 * of the same contract, an attacker holding a trusted signing key).
 *
 * Two of these rules are the schema's own (`observations` 1..1000, `roles`
 * 1..4 from the enum, `uniqueItems`, `contributors` at most 64). One is a
 * deliberate narrowing: the schema carries no `minItems` on `contributors`, so
 * a record attesting nobody is contract-valid — yet it is the one thing this
 * record type exists to state, no consumer can act on an authenticated "nobody
 * contributed", and signing it is worse than not producing it because the
 * signature lends it authority. The brick refuses it at both ends.
 *
 * TODO(context): the symmetric `minItems: 1` on `contributors` belongs to the
 * schema, in the `contracts` repository — not fixable from here. Until it lands
 * there, this brick is stricter than its contract and other producers may still
 * emit contributor-less records, which this brick now refuses on sight.
 * Tracked: https://github.com/libre-ai/contracts/issues/2
 *
 * Returns a fixed message — never record content, so it is safe to surface on
 * the untrusted path — or null when the shape holds.
 */
function lineageShapeViolation(record: {
  readonly contributors: readonly Contributor[];
  readonly observations: readonly ObservationRef[];
}): string | null {
  if (record.contributors.length === 0) {
    return "a lineage record requires at least one contributor";
  }
  if (record.contributors.length > MAX_CONTRIBUTORS) {
    return `a lineage record admits at most ${MAX_CONTRIBUTORS} contributors`;
  }
  if (record.observations.length === 0) {
    return "a lineage record requires at least one observation";
  }
  if (record.observations.length > MAX_OBSERVATIONS) {
    return `a lineage record admits at most ${MAX_OBSERVATIONS} observations`;
  }
  for (const contributor of record.contributors) {
    if (contributor.roles.length === 0) {
      return "a lineage contributor requires at least one role";
    }
    // `maxItems: 4` on roles follows from these two rules: unique values drawn
    // from a four-value enum cannot exceed four.
    if (hasDuplicates(contributor.roles)) {
      return "duplicate contributor role in a lineage record";
    }
    if (contributor.roles.some((role) => !(ROLES as readonly string[]).includes(role))) {
      return "unknown contributor role in a lineage record";
    }
  }
  if (hasDuplicates(record.contributors.map(contributorKey))) {
    return "duplicate contributor in a lineage record";
  }
  if (hasDuplicates(record.observations.map(observationKey))) {
    return "duplicate observation in a lineage record";
  }
  return null;
}

function sortedRoles(roles: readonly ContributorRole[]): ContributorRole[] {
  // Roles are a set: sort by the fixed role order so ordering does not change
  // the digest, and reject unknown roles.
  const seen = new Set<ContributorRole>();
  for (const role of roles) {
    if (!(ROLES as readonly string[]).includes(role)) {
      throw new RangeError(`unknown contributor role ${JSON.stringify(role)}`);
    }
    seen.add(role);
  }
  return ROLES.filter((role) => seen.has(role));
}

function canonicalBytes(fields: readonly string[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const field of fields) {
    const bytes = encoder.encode(field);
    parts.push(encoder.encode(`${bytes.length}:`));
    parts.push(bytes);
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function lineageContent(record: {
  id: string;
  tenantId: string;
  missionId: string;
  subjectDigest: string;
  contributors: readonly Contributor[];
  observations: readonly ObservationRef[];
  generatedAt: string;
  signingKeyId: string;
}): string[] {
  const fields: string[] = [
    LINEAGE_SCHEMA_VERSION,
    record.id,
    record.tenantId,
    record.missionId,
    record.subjectDigest,
    record.signingKeyId,
    record.generatedAt,
    String(record.contributors.length),
  ];
  for (const c of record.contributors) {
    fields.push(c.agentId, c.roles.join(","), c.contributionDigest);
  }
  fields.push(String(record.observations.length));
  for (const o of record.observations) {
    fields.push(o.id, o.digest, o.mediaType);
  }
  return fields;
}

function computeLineageDigest(fields: readonly string[]): string {
  return createHash("sha256").update(canonicalBytes(fields)).digest("hex");
}

export function buildLineage(input: LineageInput, key: SigningKey): AgentContributorLineage {
  assertDigest(input.subjectDigest, "subjectDigest");
  for (const o of input.observations) {
    assertDigest(o.digest, "observation digest");
  }
  const contributors: Contributor[] = input.contributors.map((c) => {
    assertDigest(c.contributionDigest, "contributionDigest");
    return {
      agentId: c.agentId,
      roles: sortedRoles(c.roles),
      contributionDigest: c.contributionDigest,
    };
  });
  // The shape rules run on the normalized contributors, so duplicates are
  // caught up to role ordering — stricter than the schema's `uniqueItems`,
  // which compares raw JSON values. Rejected fail-closed rather than silently
  // deduped: a duplicate signals a caller error, not a normalization case
  // (review P-01).
  //
  // A violation here is a caller mistake on input this brick was handed, hence
  // `RangeError`. The same rules broken by an untrusted record reach
  // {@link verifyLineage}, which refuses it as an integrity failure. One set of
  // rules, two audiences.
  const violation = lineageShapeViolation({ contributors, observations: input.observations });
  if (violation !== null) {
    throw new RangeError(violation);
  }
  const scaffold = {
    id: input.id,
    tenantId: input.tenantId,
    missionId: input.missionId,
    subjectDigest: input.subjectDigest,
    contributors,
    observations: [...input.observations],
    generatedAt: input.generatedAt,
    signingKeyId: key.id,
  };
  const lineageDigest = computeLineageDigest(lineageContent(scaffold));
  // Sign the digest bytes (hex) with Ed25519.
  const signature = edSign(null, encoder.encode(lineageDigest), key.privateKey).toString(
    "base64url",
  );
  return {
    schemaVersion: LINEAGE_SCHEMA_VERSION,
    ...scaffold,
    lineageDigest,
    signature,
  };
}

/**
 * Verify a lineage record under a public key. Fails closed on any alteration
 * or wrong key.
 *
 * `key.id` is not compared to `record.signingKeyId`: the caller selects the
 * key, so `key.id` is a caller-side selection label carrying no authenticated
 * claim. The record's own `signingKeyId` is already binding — it is one of the
 * signed fields of {@link lineageContent}, so substituting it changes the
 * digest and the signature check fails (unlike the envelope brick, whose
 * `integrity.keyId` sits outside its MAC and is documented there as purely
 * informational). Comparing the unauthenticated label against the signed field
 * could therefore only reject records the signature already accepts — a
 * mislabelled key registry — behind an error that says integrity failed when
 * integrity in fact holds.
 *
 * The shape rules of {@link lineageShapeViolation} are the opposite case, and
 * are enforced here: a record whose cardinality violates the contract is not a
 * lineage record, and a genuine signature cannot make it one. Refusing it
 * rejects nothing legitimate — there is no valid record on the other side of
 * that check, unlike the `key.id` comparison above. So it is refused with the
 * same content-free {@link LineageIntegrityError} as a tampered record: the
 * consumer's move is identical (do not trust this record), and callers already
 * catch that type. `buildLineage` throws `RangeError` on the same rules because
 * there the input is the caller's own — a programming error, not a refusal.
 */
export function verifyLineage(
  record: AgentContributorLineage,
  key: VerifyKey,
): { readonly valid: true } {
  if (record.schemaVersion !== LINEAGE_SCHEMA_VERSION) {
    throw new LineageIntegrityError();
  }
  // Shape before cryptography: this bounds the work done on an untrusted record
  // before it is hashed, and no signature check can rescue a record the brick
  // would refuse to sign.
  if (lineageShapeViolation(record) !== null) {
    throw new LineageIntegrityError();
  }
  // Recompute the digest from the content: a tampered field changes it.
  const expectedDigest = computeLineageDigest(lineageContent(record));
  if (expectedDigest !== record.lineageDigest) {
    throw new LineageIntegrityError();
  }
  let ok: boolean;
  try {
    ok = edVerify(
      null,
      encoder.encode(record.lineageDigest),
      key.publicKey,
      Buffer.from(record.signature, "base64url"),
    );
  } catch {
    throw new LineageIntegrityError();
  }
  if (!ok) {
    throw new LineageIntegrityError();
  }
  return { valid: true };
}
