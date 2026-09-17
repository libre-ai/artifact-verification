import { describe, expect, test } from "bun:test";
import { createHash, sign as edSign, generateKeyPairSync } from "node:crypto";
import {
  type AgentContributorLineage,
  buildLineage,
  type Contributor,
  type LineageInput,
  LineageIntegrityError,
  type ObservationRef,
  type SigningKey,
  type VerifyKey,
  verifyLineage,
} from "./index";

/**
 * Provenance brick (couche 3): builds and verifies AgentContributorLineage v1
 * records — the BOT-C contribution lineage. The lineage digest is signed with
 * Ed25519 (asymmetric origin authentication, unlike the envelope's symmetric
 * HMAC). Dev keys here; the production signing key is an owner key ceremony
 * (deferred, WP-G2-Z01 / P3).
 */

function devKeys(id: string): { signing: SigningKey; verify: VerifyKey } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { signing: { id, privateKey }, verify: { id, publicKey } };
}

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

const INPUT: LineageInput = {
  id: "urn:libre-ai:lineage:rec-1",
  tenantId: "ten_aaaaaaaaaaaaaaaa",
  missionId: "urn:libre-ai:mission:m-1",
  subjectDigest: DIGEST_A,
  contributors: [
    { agentId: "agent_forge_01", roles: ["author", "fixer"], contributionDigest: DIGEST_B },
  ],
  observations: [
    { id: "urn:libre-ai:artifact:pr-137", digest: DIGEST_A, mediaType: "text/markdown" },
  ],
  generatedAt: "2026-07-20T00:00:00.000Z",
};

type UnsignedLineage = Omit<AgentContributorLineage, "lineageDigest" | "signature">;

const UNSIGNED: UnsignedLineage = {
  schemaVersion: "libre-ai.agent-contributor-lineage.v1",
  id: INPUT.id,
  tenantId: INPUT.tenantId,
  missionId: INPUT.missionId,
  subjectDigest: INPUT.subjectDigest,
  contributors: INPUT.contributors,
  observations: INPUT.observations,
  generatedAt: INPUT.generatedAt,
  signingKeyId: "provkey_01",
};

/**
 * A producer that is not `buildLineage`: it signs the record it is handed with
 * a key the verifier trusts. Models this brick before its build-time guards and
 * any other implementation of `agent-contributor-lineage.v1` — the schema admits
 * `contributors: []`, so such a producer is entitled to emit one, and its
 * signature is genuine. This is the attacker-free scenario that matters: what
 * `verifyLineage` accepts is not bounded by what `buildLineage` produces.
 *
 * The canonical encoding is re-implemented here rather than imported on purpose:
 * a test that inherits the encoding it audits proves nothing about the records
 * other producers emit. Fidelity against `buildLineage` is asserted below.
 */
function signAsForeignProducer(record: UnsignedLineage, key: SigningKey): AgentContributorLineage {
  const fields: string[] = [
    record.schemaVersion,
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
  const canonical = Buffer.concat(
    fields.flatMap((field) => {
      const bytes = Buffer.from(field, "utf8");
      return [Buffer.from(`${bytes.length}:`, "utf8"), bytes];
    }),
  );
  const lineageDigest = createHash("sha256").update(canonical).digest("hex");
  const signature = edSign(null, Buffer.from(lineageDigest, "utf8"), key.privateKey).toString(
    "base64url",
  );
  return { ...record, lineageDigest, signature };
}

function contributorsOfSize(size: number): Contributor[] {
  return Array.from({ length: size }, (_, index) => ({
    agentId: `agent_forge_${index}`,
    roles: ["author"] as const,
    contributionDigest: DIGEST_B,
  }));
}

function observationsOfSize(size: number): ObservationRef[] {
  return Array.from({ length: size }, (_, index) => ({
    id: `urn:libre-ai:artifact:obs-${index}`,
    digest: DIGEST_A,
    mediaType: "text/markdown",
  }));
}

describe("buildLineage", () => {
  test("produces a schema-shaped, signed record", () => {
    const { signing } = devKeys("provkey_01");
    const rec = buildLineage(INPUT, signing);
    expect(rec.schemaVersion).toBe("libre-ai.agent-contributor-lineage.v1");
    expect(rec.signingKeyId).toBe("provkey_01");
    expect(rec.lineageDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(rec.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
    expect(rec.contributors[0]?.roles).toEqual(["author", "fixer"]);
  });

  test("the lineage digest is deterministic and order-independent in roles", () => {
    const { signing } = devKeys("provkey_01");
    const a = buildLineage(INPUT, signing);
    const b = buildLineage(
      { ...INPUT, contributors: [{ ...INPUT.contributors[0]!, roles: ["fixer", "author"] }] },
      signing,
    );
    // Roles are a set — order must not change the digest.
    expect(a.lineageDigest).toBe(b.lineageDigest);
  });

  test("rejects a non-opaque subject digest", () => {
    const { signing } = devKeys("provkey_01");
    expect(() => buildLineage({ ...INPUT, subjectDigest: "not-a-digest" }, signing)).toThrow(
      /digest/i,
    );
  });

  test("rejects an empty observation set (schema minItems 1)", () => {
    const { signing } = devKeys("provkey_01");
    expect(() => buildLineage({ ...INPUT, observations: [] }, signing)).toThrow(/observation/i);
  });

  test("rejects an empty contributor set (a lineage attests someone)", () => {
    const { signing } = devKeys("provkey_01");
    expect(() => buildLineage({ ...INPUT, contributors: [] }, signing)).toThrow(
      /at least one contributor/i,
    );
  });

  test("rejects more than 64 contributors (schema maxItems)", () => {
    const { signing } = devKeys("provkey_01");
    expect(() =>
      buildLineage({ ...INPUT, contributors: contributorsOfSize(64) }, signing),
    ).not.toThrow();
    expect(() => buildLineage({ ...INPUT, contributors: contributorsOfSize(65) }, signing)).toThrow(
      /at most 64 contributors/,
    );
  });

  test("rejects more than 1000 observations (schema maxItems)", () => {
    const { signing } = devKeys("provkey_01");
    expect(() =>
      buildLineage({ ...INPUT, observations: observationsOfSize(1000) }, signing),
    ).not.toThrow();
    expect(() =>
      buildLineage({ ...INPUT, observations: observationsOfSize(1001) }, signing),
    ).toThrow(/at most 1000 observations/);
  });

  test("rejects a contributor holding no role (schema minItems 1 on roles)", () => {
    const { signing } = devKeys("provkey_01");
    expect(() =>
      buildLineage(
        {
          ...INPUT,
          contributors: [{ agentId: "agent_forge_01", roles: [], contributionDigest: DIGEST_B }],
        },
        signing,
      ),
    ).toThrow(/at least one role/);
  });

  test("rejects duplicate contributors (schema uniqueItems, review P-01)", () => {
    const { signing } = devKeys("provkey_01");
    const dup = INPUT.contributors[0]!;
    expect(() => buildLineage({ ...INPUT, contributors: [dup, { ...dup }] }, signing)).toThrow(
      /duplicate contributor/i,
    );
  });

  test("rejects duplicate observations (schema uniqueItems)", () => {
    const { signing } = devKeys("provkey_01");
    const obs = INPUT.observations[0]!;
    expect(() => buildLineage({ ...INPUT, observations: [obs, { ...obs }] }, signing)).toThrow(
      /duplicate observation/i,
    );
  });
});

describe("verifyLineage", () => {
  test("accepts an intact record under the right key", () => {
    const { signing, verify } = devKeys("provkey_01");
    const rec = buildLineage(INPUT, signing);
    expect(verifyLineage(rec, verify)).toEqual({ valid: true });
  });

  test("detects a tampered contributor digest (digest + signature both fail)", () => {
    const { signing, verify } = devKeys("provkey_01");
    const rec = buildLineage(INPUT, signing);
    const tampered = {
      ...rec,
      contributors: [{ ...rec.contributors[0]!, contributionDigest: "c".repeat(64) }],
    };
    expect(() => verifyLineage(tampered, verify)).toThrow(LineageIntegrityError);
  });

  test("detects a recomputed digest with a stale signature", () => {
    const { signing, verify } = devKeys("provkey_01");
    const rec = buildLineage(INPUT, signing);
    // Attacker fixes the digest to match the tamper but cannot re-sign.
    const forged = { ...rec, lineageDigest: "d".repeat(64) };
    expect(() => verifyLineage(forged, verify)).toThrow(LineageIntegrityError);
  });

  test("fails closed under a different key", () => {
    const { signing } = devKeys("provkey_01");
    const other = devKeys("provkey_02");
    const rec = buildLineage(INPUT, signing);
    expect(() => verifyLineage(rec, other.verify)).toThrow(LineageIntegrityError);
  });

  test("the foreign producer reproduces the canonical encoding (helper fidelity)", () => {
    const { signing, verify } = devKeys("provkey_01");
    const built = buildLineage(INPUT, signing);
    const foreign = signAsForeignProducer(UNSIGNED, signing);
    // Same digest and — Ed25519 being deterministic — the same signature: the
    // refusals below are about the record's shape, not a mis-encoded fixture.
    expect(foreign.lineageDigest).toBe(built.lineageDigest);
    expect(foreign.signature).toBe(built.signature);
    expect(verifyLineage(foreign, verify)).toEqual({ valid: true });
  });

  test("refuses a genuinely signed record that attests no contributor", () => {
    const { signing, verify } = devKeys("provkey_01");
    const record = signAsForeignProducer({ ...UNSIGNED, contributors: [] }, signing);
    // The signature is valid and the digest is intact — the build-time guard
    // alone would let this through, because it never runs on this path.
    expect(record.contributors).toEqual([]);
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("refuses a signed record above the contributor bound (schema maxItems 64)", () => {
    const { signing, verify } = devKeys("provkey_01");
    const record = signAsForeignProducer(
      { ...UNSIGNED, contributors: contributorsOfSize(65) },
      signing,
    );
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("refuses a signed record above the observation bound (schema maxItems 1000)", () => {
    const { signing, verify } = devKeys("provkey_01");
    const record = signAsForeignProducer(
      { ...UNSIGNED, observations: observationsOfSize(1001) },
      signing,
    );
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("refuses a signed record whose observation set is empty (schema minItems 1)", () => {
    const { signing, verify } = devKeys("provkey_01");
    const record = signAsForeignProducer({ ...UNSIGNED, observations: [] }, signing);
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("refuses a signed record whose contributor holds no role", () => {
    const { signing, verify } = devKeys("provkey_01");
    const record = signAsForeignProducer(
      {
        ...UNSIGNED,
        contributors: [{ agentId: "agent_forge_01", roles: [], contributionDigest: DIGEST_B }],
      },
      signing,
    );
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("refuses a signed record carrying an unknown role", () => {
    const { signing, verify } = devKeys("provkey_01");
    const record = signAsForeignProducer(
      {
        ...UNSIGNED,
        contributors: [
          {
            agentId: "agent_forge_01",
            // Outside the schema enum: reachable from an untrusted record, where
            // no compiler stands between the wire and the verifier.
            roles: ["owner"] as unknown as Contributor["roles"],
            contributionDigest: DIGEST_B,
          },
        ],
      },
      signing,
    );
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("refuses a signed record carrying duplicate contributors (schema uniqueItems)", () => {
    const { signing, verify } = devKeys("provkey_01");
    const contributor = UNSIGNED.contributors[0] as Contributor;
    const record = signAsForeignProducer(
      { ...UNSIGNED, contributors: [contributor, { ...contributor }] },
      signing,
    );
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("refuses a signed record carrying duplicate observations (schema uniqueItems)", () => {
    const { signing, verify } = devKeys("provkey_01");
    const observation = UNSIGNED.observations[0] as ObservationRef;
    const record = signAsForeignProducer(
      { ...UNSIGNED, observations: [observation, { ...observation }] },
      signing,
    );
    expect(() => verifyLineage(record, verify)).toThrow(LineageIntegrityError);
  });

  test("the error discloses no contribution content", () => {
    const { signing, verify } = devKeys("provkey_01");
    const rec = buildLineage(INPUT, signing);
    const tampered = { ...rec, subjectDigest: "e".repeat(64) };
    try {
      verifyLineage(tampered, verify);
      throw new Error("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(LineageIntegrityError);
      expect(String(error)).not.toContain("e".repeat(64));
    }
  });
});
