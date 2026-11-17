//! Signed manifest verification against the candidate contract
//! `artifact-manifest-signatures.v1` / `signing-keys.v1` of schemas-and-contracts.
//!
//! The contract vectors and the strict Ed25519 vectors are read from the
//! schemas-and-contracts revision that Cargo compiled (located by `cargo metadata`), never
//! copied here: bumping the pin replays the corpus of the new revision.

use ed25519_dalek::{Signer, SigningKey};
use libre_ai_artifact::{
    ArtifactRefusal, ArtifactVerifier, CandidateFile, MAX_SIGNATURES, MAX_TRUSTED_KEYS,
    SIGNED_MESSAGE_DOMAIN, TrustedKeySet, VerifiedSignatures, artifact_content_digest,
    canonical_document_digest, ed25519_point_is_admissible, sha256_hex,
};
use libre_ai_contract_types::strict_json;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::Command;

const NOW: &str = "2026-10-15T12:00:00.000Z";
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const SPKI_X25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

// ---------------------------------------------------------------- test material

fn verifier() -> ArtifactVerifier {
    ArtifactVerifier::embedded().expect("embedded contracts compile")
}

/// The `libre-ai-contract-types` package Cargo resolved, as `cargo metadata` reports it.
fn contract_types_package() -> Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"),
        ])
        .output()
        .expect("cargo metadata runs");
    assert!(output.status.success(), "cargo metadata failed");
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("metadata is JSON");
    let package = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "libre-ai-contract-types")
        .expect("libre-ai-contract-types is a dependency")
        .clone();
    println!("contract vectors from {}", package["id"]);
    package
}

/// The Git revision in a Cargo git package id (`git+<url>?rev=<rev>#<rev>`).
fn pinned_revision(package_id: &str) -> &str {
    let revision = package_id
        .split_once("?rev=")
        .and_then(|(_, rest)| rest.split_once('#'))
        .map(|(revision, _)| revision)
        .expect("git revision in the package id");
    assert!(
        revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "full git revision in the package id"
    );
    revision
}

/// Bytes of `relative` in the schemas-and-contracts revision compiled as
/// `libre-ai-contract-types`.
///
/// From its git source, Cargo compiles a checkout of the whole repository, so the
/// fixtures sit two levels above `crates/sdk-rs`. The fleet composition substitutes
/// a directory source holding the crate subtree only, materialised from the
/// schemas-and-contracts checkout it places beside this repository at the same
/// revision: the fixture is then read from that checkout's committed objects at the
/// revision Cargo resolved (`git show <rev>:<path>`), never from its working tree.
fn contract_fixture_bytes(relative: &str) -> Vec<u8> {
    let package = contract_types_package();
    let manifest_path = PathBuf::from(package["manifest_path"].as_str().expect("path"));
    let crate_dir = manifest_path.parent().expect("crate directory");
    if crate_dir.ends_with("crates/sdk-rs") {
        let root = crate_dir.ancestors().nth(2).expect("repository root");
        return std::fs::read(root.join(relative)).expect("declared contract fixture is readable");
    }
    let revision = pinned_revision(package["id"].as_str().expect("package id"));
    let output = Command::new("git")
        .args([
            "-C",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../schemas-and-contracts"),
            "show",
            &format!("{revision}:{relative}"),
        ])
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "declared contract fixture {relative} is readable at {revision} in the composed checkout"
    );
    output.stdout
}

/// A declared fixture that cannot be read fails the test, never skips it.
fn contract_fixture(relative: &str) -> Value {
    serde_json::from_slice(&contract_fixture_bytes(relative)).expect("contract fixture is JSON")
}

fn base64_value(character: u8) -> u32 {
    match character {
        b'A'..=b'Z' => u32::from(character - b'A'),
        b'a'..=b'z' => u32::from(character - b'a') + 26,
        b'0'..=b'9' => u32::from(character - b'0') + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        other => panic!("not a Base64 character: {other}"),
    }
}

/// Test-side decoder of the vectors' unpadded Base64url (independent of the crate's).
fn b64url(text: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for character in text.bytes() {
        buffer = (buffer << 6) | base64_value(character);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    output
}

fn b64_encode(bytes: &[u8], url: bool) -> String {
    let alphabet: &[u8; 64] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let block = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |block, (index, byte)| {
                block | (u32::from(*byte) << (16 - 8 * index))
            });
        for index in 0..=chunk.len() {
            output.push(char::from(
                alphabet[((block >> (18 - 6 * index)) & 63) as usize],
            ));
        }
        if !url {
            for _ in chunk.len()..3 {
                output.push('=');
            }
        }
    }
    output
}

fn pem(der: &[u8]) -> String {
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        b64_encode(der, false)
    )
}

fn key_id(public_key: &[u8]) -> String {
    format!("ed25519-{}", sha256_hex(public_key))
}

struct TestKey {
    signing: SigningKey,
    public: [u8; 32],
    id: String,
}

/// Ephemeral key from a fixed public test label; never trusted outside tests.
fn test_key(label: &str) -> TestKey {
    let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    TestKey {
        id: key_id(&public),
        signing,
        public,
    }
}

fn key_entry(
    public_key: &[u8],
    artifact_types: &[&str],
    activated_at: &str,
    revoked_at: Option<&str>,
) -> Value {
    let mut der = SPKI_ED25519_PREFIX.to_vec();
    der.extend_from_slice(public_key);
    let mut entry = json!({
        "signingKeyId": key_id(public_key),
        "algorithm": "Ed25519",
        "publicKey": pem(&der),
        "purpose": "Test key: artifact manifest signatures",
        "artifactTypes": artifact_types,
        "activatedAt": activated_at,
        "revokedAt": revoked_at,
        "witness": {
            "signatory": "key-custodian",
            "attestedAt": activated_at,
            "comment": "Synthetic test key; its seed is published."
        }
    });
    if let Some(revoked_at) = revoked_at {
        entry["revocationReason"] = json!("Key compromise (test)");
        entry["revocationWitness"] = json!({
            "signatory": "key-custodian",
            "discoveredAt": revoked_at
        });
    }
    entry
}

fn registry_octets(entries: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schemaVersion": "libre-ai.signing-keys.v1",
        "keys": entries
    }))
    .expect("registry serializes")
}

fn admit(entries: Vec<Value>) -> Result<TrustedKeySet, ArtifactRefusal> {
    verifier().admit_signing_keys(&registry_octets(entries))
}

/// Test-side signed message of S4 (the crate's builder is crate-private):
/// `UTF8(schemaVersion) || 0x00 || SHA-256(RFC 8785(manifest))`. Checked against
/// the contract's published messages below.
fn signed_message(manifest: &Value) -> Vec<u8> {
    let domain = manifest["schemaVersion"].as_str().expect("schemaVersion");
    let canonical = strict_json::canonicalize(manifest).expect("RFC 8785 form");
    let mut message = domain.as_bytes().to_vec();
    message.push(0x00);
    message.extend_from_slice(&Sha256::digest(&canonical));
    message
}

fn sign(key: &TestKey, manifest: &Value) -> String {
    let message = signed_message(manifest);
    b64_encode(&key.signing.sign(&message).to_bytes(), true)
}

fn record(signatures: &[(&str, String)]) -> Vec<u8> {
    let signatures = signatures
        .iter()
        .map(|(id, signature)| json!({ "signingKeyId": id, "signature": signature }))
        .collect::<Vec<_>>();
    serde_json::to_vec(&json!({
        "schemaVersion": "libre-ai.artifact-manifest-signatures.v1",
        "signatures": signatures
    }))
    .expect("record serializes")
}

fn candidate_files() -> Vec<CandidateFile<'static>> {
    vec![
        CandidateFile {
            path: "bin/tool",
            media_type: "application/octet-stream",
            bytes: b"\x7fELF release binary",
        },
        CandidateFile {
            path: "share/notice.txt",
            media_type: "text/plain",
            bytes: b"notice\n",
        },
    ]
}

/// A manifest of `artifact_type` over `candidate_files()`, its evidence bound.
fn manifest(artifact_type: &str) -> (Value, Value) {
    let files = candidate_files();
    let id = "urn:libre-ai:artifact:signed-1";
    let digest = artifact_content_digest(&files).expect("content digest");
    let evidence = json!({
        "schemaVersion": "libre-ai.evidence-report.v1",
        "id": "urn:libre-ai:evidence:signed-1",
        "subject": id,
        "subjectDigest": digest,
        "status": "pass",
        "checks": [{ "id": "artifact-integrity", "status": "pass", "ruleVersion": "1.0.0" }],
        "generatedAt": "2026-07-17T00:00:00Z",
        "producer": { "name": "artifact-qualification", "version": "1.0.0" }
    });
    let manifest = json!({
        "schemaVersion": "libre-ai.artifact-manifest.v1",
        "id": id,
        "artifactType": artifact_type,
        "createdAt": "2026-07-17T00:00:01Z",
        "digest": digest,
        "files": files.iter().map(|file| json!({
            "path": file.path,
            "size": file.bytes.len(),
            "digest": sha256_hex(file.bytes),
            "mediaType": file.media_type,
        })).collect::<Vec<_>>(),
        "evidenceReport": {
            "id": evidence["id"],
            "digest": canonical_document_digest(&evidence).expect("evidence digest"),
            "mediaType": "application/json"
        }
    });
    (manifest, evidence)
}

fn octets(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serializes")
}

type Outcome = Result<(Vec<String>, usize), ArtifactRefusal>;

fn outcome(result: Result<VerifiedSignatures, ArtifactRefusal>) -> Outcome {
    result.map(|verified| (verified.verified_key_ids, verified.ignored_unknown_key_ids))
}

fn accepted(ids: &[&str], ignored: usize) -> Outcome {
    let mut ids = ids.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
    ids.sort();
    Ok((ids, ignored))
}

/// Full chain on the release of `manifest()`, files intact.
fn verify_release(
    keys: &TrustedKeySet,
    manifest: &Value,
    evidence: &Value,
    signatures: &[(&str, String)],
) -> Outcome {
    verifier()
        .verify_signed_candidate(
            &octets(manifest),
            Some(evidence),
            &candidate_files(),
            &record(signatures),
            keys,
            NOW,
        )
        .map(|verified| {
            (
                verified.signatures.verified_key_ids,
                verified.signatures.ignored_unknown_key_ids,
            )
        })
}

// ---------------------------------------------------------------- contract vectors

fn refusal_from_code(code: &str) -> ArtifactRefusal {
    use ArtifactRefusal::*;
    [
        KeySetInvalid,
        ManifestSchemaInvalid,
        SignatureRequired,
        SignatureMalformed,
        SignatureKeyUnknown,
        SignatureKeyNotActive,
        SignatureKeyNotAuthorized,
        SignatureInvalid,
    ]
    .into_iter()
    .find(|refusal| refusal.code() == format!("artifact.{code}"))
    .unwrap_or_else(|| panic!("unmapped contract refusal code {code}"))
}

#[test]
fn every_contract_vector_yields_its_expected_outcome() {
    let vectors =
        contract_fixture("contracts/fixtures/artifact-manifest-signatures-v1/vectors.json");
    assert_eq!(vectors["domain"], SIGNED_MESSAGE_DOMAIN);
    let verifier = verifier();
    let mut failures = Vec::new();

    // Published signed messages: the test-side builder that signs every fixture of this
    // file must reproduce them (the crate's builder is checked by its unit tests).
    let messages = vectors["messages"].as_object().expect("messages");
    for (name, expected) in messages {
        let manifest_octets = b64url(vectors["manifestOctets"][name].as_str().expect("octets"));
        let manifest = strict_json::parse(&manifest_octets).expect("strict manifest");
        let built = signed_message(&manifest);
        let expected = b64url(expected.as_str().expect("message"));
        let verdict = if built == expected { "ok" } else { "not ok" };
        println!("{verdict} message {name}");
        if built != expected {
            failures.push(format!("message {name}"));
        }
    }

    let registry_vectors = vectors["registryVectors"]
        .as_array()
        .expect("registry vectors");
    let mut registry_executed = 0_usize;
    for vector in registry_vectors {
        let id = vector["id"].as_str().expect("id");
        let input = match vector["registryOctets"].as_str() {
            Some(text) => b64url(text),
            None => octets(&vector["registry"]),
        };
        let expected = match vector["expected"]["outcome"].as_str() {
            Some("admitted") => Ok(()),
            Some("refused") => Err(refusal_from_code(
                vector["expected"]["refusal"].as_str().expect("refusal"),
            )),
            other => panic!("unknown outcome {other:?} in {id}"),
        };
        let obtained = verifier.admit_signing_keys(&input).map(|_| ());
        registry_executed += 1;
        let verdict = if obtained == expected { "ok" } else { "not ok" };
        println!("{verdict} registry {id}: expected {expected:?}, obtained {obtained:?}");
        if obtained != expected {
            failures.push(format!("registry {id}"));
        }
    }

    let signature_vectors = vectors["signatureVectors"]
        .as_array()
        .expect("signature vectors");
    let mut signature_executed = 0_usize;
    for vector in signature_vectors {
        let id = vector["id"].as_str().expect("id");
        let manifest_name = vector["manifest"].as_str().expect("manifest name");
        let manifest_octets = b64url(
            vectors["manifestOctets"][manifest_name]
                .as_str()
                .expect("manifest octets"),
        );
        let registry_name = vector["registry"].as_str().expect("registry name");
        // A registry that fails to admit is a failure of this vector, never a skip.
        let keys = match verifier.admit_signing_keys(&octets(&vectors["registries"][registry_name]))
        {
            Ok(keys) => keys,
            Err(refusal) => {
                println!("not ok signature {id}: registry {registry_name} refused {refusal:?}");
                failures.push(format!("signature {id}"));
                signature_executed += 1;
                continue;
            }
        };
        let record_octets = match vector["recordOctets"].as_str() {
            Some(text) => b64url(text),
            None => octets(&vector["record"]),
        };
        let expected = match vector["expected"]["outcome"].as_str() {
            Some("accepted") => Ok((
                vector["expected"]["verifiedKeyIds"]
                    .as_array()
                    .expect("verified ids")
                    .iter()
                    .map(|id| id.as_str().expect("id").to_owned())
                    .collect::<Vec<_>>(),
                usize::try_from(
                    vector["expected"]["ignoredUnknownKeyIds"]
                        .as_u64()
                        .expect("ignored count"),
                )
                .expect("count fits"),
            )),
            Some("refused") => Err(refusal_from_code(
                vector["expected"]["refusal"].as_str().expect("refusal"),
            )),
            other => panic!("unknown outcome {other:?} in {id}"),
        };
        let obtained = outcome(verifier.verify_manifest_signatures(
            &manifest_octets,
            &record_octets,
            &keys,
            vector["now"].as_str().expect("now"),
        ));
        signature_executed += 1;
        let verdict = if obtained == expected { "ok" } else { "not ok" };
        println!("{verdict} signature {id}: expected {expected:?}, obtained {obtained:?}");
        if obtained != expected {
            failures.push(format!("signature {id}"));
        }
    }

    println!(
        "registry vectors: {registry_executed}/{} executed; signature vectors: {signature_executed}/{} executed; messages: {}; failures: {}",
        registry_vectors.len(),
        signature_vectors.len(),
        messages.len(),
        failures.len()
    );
    assert!(registry_executed > 0 && signature_executed > 0 && !messages.is_empty());
    assert_eq!(registry_executed, registry_vectors.len());
    assert_eq!(signature_executed, signature_vectors.len());
    assert!(failures.is_empty(), "failing vectors: {failures:?}");
}

#[test]
fn strict_point_vectors_match_the_admission_profile() {
    let vectors = contract_fixture("contracts/fixtures/build-brief-v2/strict-ed25519-vectors.json");
    let points = vectors["points"].as_array().expect("points");
    let mut admissible = 0_usize;
    let mut failures = Vec::new();
    for point in points {
        let id = point["id"].as_str().expect("id");
        let expected = point["admissible"].as_bool().expect("admissible");
        let obtained =
            ed25519_point_is_admissible(&b64url(point["point"].as_str().expect("point")));
        admissible += usize::from(obtained);
        if obtained != expected {
            failures.push(id.to_owned());
        }
    }
    println!(
        "points read {}, admissible {admissible}, refused {}",
        points.len(),
        points.len() - admissible
    );
    assert!(failures.is_empty(), "points: {failures:?}");
    assert_eq!(points.len(), 24);
    assert_eq!(admissible, 3);
}

// The 51 strict signature vectors against the raw primitive are a unit test of the
// crate (`src/signature_contract_tests.rs`): the primitive is crate-private.

#[test]
fn every_refused_strict_point_refuses_the_registry() {
    let vectors = contract_fixture("contracts/fixtures/build-brief-v2/strict-ed25519-vectors.json");
    let mut refused = 0_usize;
    for point in vectors["points"].as_array().expect("points") {
        let id = point["id"].as_str().expect("id");
        let octets = b64url(point["point"].as_str().expect("point"));
        let entry = key_entry(&octets, &["release"], "2026-01-01T00:00:00.000Z", None);
        let obtained = admit(vec![entry]).map(|keys| keys.len());
        if point["admissible"].as_bool().expect("admissible") {
            // Control: the same construction admits an admissible point (K1 and K3 hold).
            assert_eq!(obtained, Ok(1), "{id}");
        } else if obtained == Err(ArtifactRefusal::KeySetInvalid) {
            refused += 1;
        } else {
            panic!("{id}: expected KeySetInvalid, obtained {obtained:?}");
        }
    }
    assert_eq!(refused, 21);
}

// ---------------------------------------------------------------- registry admission

#[test]
fn key_set_refusals_of_the_brief() {
    let a = test_key("artifact-verification-test-key-A");
    let b = test_key("artifact-verification-test-key-B");
    let active = "2026-01-01T00:00:00.000Z";
    let good = || key_entry(&a.public, &["release"], active, None);

    let mut empty_id = good();
    empty_id["signingKeyId"] = json!("");
    let mut repeated_key = key_entry(&b.public, &["release"], active, None);
    repeated_key["publicKey"] = good()["publicKey"].clone();
    let mut x25519 = good();
    let mut der = SPKI_X25519_PREFIX.to_vec();
    der.extend_from_slice(&a.public);
    x25519["publicKey"] = json!(pem(&der));
    let mut long_der = good();
    let mut der = SPKI_ED25519_PREFIX.to_vec();
    der.extend_from_slice(&a.public);
    der.push(0);
    long_der["publicKey"] = json!(pem(&der));
    let revoked_at_activation = key_entry(&a.public, &["release"], active, Some(active));
    let sixty_five = (0..=MAX_TRUSTED_KEYS)
        .map(|index| {
            key_entry(
                &test_key(&format!("artifact-verification-bulk-{index}")).public,
                &["release"],
                active,
                None,
            )
        })
        .collect::<Vec<_>>();
    let sixty_four = sixty_five[..MAX_TRUSTED_KEYS].to_vec();

    let cases: Vec<(&str, Vec<Value>)> = vec![
        ("empty set", vec![]),
        ("65 entries", sixty_five),
        ("empty identifier", vec![empty_id]),
        ("repeated identifier", vec![good(), good()]),
        ("same key under two identifiers", vec![good(), repeated_key]),
        ("X25519 SPKI", vec![x25519]),
        ("45-octet DER", vec![long_der]),
        (
            "revokedAt equal to activatedAt",
            vec![revoked_at_activation],
        ),
    ];
    for (name, entries) in cases {
        let obtained = admit(entries).map(|keys| keys.len());
        println!("{name}: {obtained:?}");
        assert_eq!(obtained, Err(ArtifactRefusal::KeySetInvalid), "{name}");
    }
    // Controls: the bound itself and a key that authorizes nothing are admitted.
    assert_eq!(
        admit(sixty_four).map(|keys| keys.len()),
        Ok(MAX_TRUSTED_KEYS)
    );
    let nothing = key_entry(&a.public, &[], active, None);
    let keys = admit(vec![nothing]).expect("artifactTypes [] is admitted");
    assert!(!keys.is_empty());
}

#[test]
fn a_registry_refused_by_strict_octets_yields_no_key_set() {
    let a = test_key("artifact-verification-test-key-A");
    let text = String::from_utf8(registry_octets(vec![key_entry(
        &a.public,
        &["release"],
        "2026-01-01T00:00:00.000Z",
        None,
    )]))
    .expect("UTF-8");
    let duplicated = text.replacen("\"purpose\":", "\"purpose\":\"first\",\"purpose\":", 1);
    assert_ne!(text, duplicated);
    assert_eq!(
        verifier()
            .admit_signing_keys(duplicated.as_bytes())
            .map(|keys| keys.len()),
        Err(ArtifactRefusal::KeySetInvalid)
    );
}

// ---------------------------------------------------------------- rotation matrix

#[test]
fn rotation_matrix() {
    let a = test_key("artifact-verification-test-key-A");
    let b = test_key("artifact-verification-test-key-B");
    let r = test_key("artifact-verification-test-key-R");
    let entry_a = || key_entry(&a.public, &["release"], "2026-01-01T00:00:00.000Z", None);
    let entry_a_revoked = || {
        key_entry(
            &a.public,
            &["release"],
            "2026-01-01T00:00:00.000Z",
            Some("2026-10-01T00:00:00.000Z"),
        )
    };
    let entry_b = || key_entry(&b.public, &["release"], "2026-06-01T00:00:00.000Z", None);
    let entry_r = || key_entry(&r.public, &["release"], "2026-01-01T00:00:00.000Z", None);
    // A failed setup is a failure of the matrix, never a skipped case.
    let before = admit(vec![entry_a()]).expect("before");
    let transition = admit(vec![entry_a(), entry_b()]).expect("transition");
    let after = admit(vec![entry_a_revoked(), entry_b()]).expect("after");
    let retired = admit(vec![entry_b()]).expect("retired");
    let transition_r = admit(vec![entry_a(), entry_b(), entry_r()]).expect("transition + R");

    let (release, evidence) = manifest("release");
    let (dataset, dataset_evidence) = manifest("dataset");
    let sig_a = sign(&a, &release);
    let sig_b = sign(&b, &release);
    let (id_a, id_b, id_r) = (a.id.as_str(), b.id.as_str(), r.id.as_str());

    let cases: Vec<(&str, Outcome, Outcome)> = vec![
        (
            "1 before, signed A",
            verify_release(&before, &release, &evidence, &[(id_a, sig_a.clone())]),
            accepted(&[id_a], 0),
        ),
        (
            "2 before, signed B only",
            verify_release(&before, &release, &evidence, &[(id_b, sig_b.clone())]),
            Err(ArtifactRefusal::SignatureKeyUnknown),
        ),
        (
            "3 before, signed A and B",
            verify_release(
                &before,
                &release,
                &evidence,
                &[(id_a, sig_a.clone()), (id_b, sig_b.clone())],
            ),
            accepted(&[id_a], 1),
        ),
        (
            "4 transition, signed A",
            verify_release(&transition, &release, &evidence, &[(id_a, sig_a.clone())]),
            accepted(&[id_a], 0),
        ),
        (
            "5 transition, signed B",
            verify_release(&transition, &release, &evidence, &[(id_b, sig_b.clone())]),
            accepted(&[id_b], 0),
        ),
        (
            "6 transition, signed A and B",
            verify_release(
                &transition,
                &release,
                &evidence,
                &[(id_a, sig_a.clone()), (id_b, sig_b.clone())],
            ),
            accepted(&[id_a, id_b], 0),
        ),
        (
            "7 transition, A signature labeled B",
            verify_release(&transition, &release, &evidence, &[(id_b, sig_a.clone())]),
            Err(ArtifactRefusal::SignatureInvalid),
        ),
        (
            "8 after, signed A only",
            verify_release(&after, &release, &evidence, &[(id_a, sig_a.clone())]),
            Err(ArtifactRefusal::SignatureKeyNotActive),
        ),
        (
            "9 after, signed A and B",
            verify_release(
                &after,
                &release,
                &evidence,
                &[(id_a, sig_a.clone()), (id_b, sig_b.clone())],
            ),
            Err(ArtifactRefusal::SignatureKeyNotActive),
        ),
        (
            "10 after, signed B",
            verify_release(&after, &release, &evidence, &[(id_b, sig_b.clone())]),
            accepted(&[id_b], 0),
        ),
        (
            "11 retired, signed A only",
            verify_release(&retired, &release, &evidence, &[(id_a, sig_a.clone())]),
            Err(ArtifactRefusal::SignatureKeyUnknown),
        ),
        (
            "12a transition + R, dataset signed R",
            verify_release(
                &transition_r,
                &dataset,
                &dataset_evidence,
                &[(id_r, sign(&r, &dataset))],
            ),
            Err(ArtifactRefusal::SignatureKeyNotAuthorized),
        ),
        (
            "12b transition + R, release signed R, evidence bound",
            verify_release(
                &transition_r,
                &release,
                &evidence,
                &[(id_r, sign(&r, &release))],
            ),
            accepted(&[id_r], 0),
        ),
    ];

    let mut executed = std::collections::BTreeSet::new();
    let mut failures = 0_usize;
    for (name, obtained, expected) in &cases {
        let verdict = if obtained == expected { "ok" } else { "not ok" };
        println!("{verdict} {name}: expected {expected:?}, obtained {obtained:?}");
        failures += usize::from(obtained != expected);
        executed.insert(
            name.split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or(""),
        );
    }
    println!("rotation cases executed: {}", executed.len());
    assert_eq!(executed.len(), 12, "rotation matrix must run 12 cases");
    assert_eq!(failures, 0);
}

// ---------------------------------------------------------------- precedence and chain

#[test]
fn first_of_two_adjacent_defects_is_reported() {
    let a = test_key("artifact-verification-test-key-A");
    let unknown = test_key("artifact-verification-test-key-unknown");
    let keys = admit(vec![key_entry(
        &a.public,
        &["release"],
        "2026-01-01T00:00:00.000Z",
        None,
    )])
    .expect("keys");
    let revoked = admit(vec![key_entry(
        &a.public,
        &["release"],
        "2026-01-01T00:00:00.000Z",
        Some("2026-10-01T00:00:00.000Z"),
    )])
    .expect("revoked keys");
    let (release, evidence) = manifest("release");
    let (other, _) = manifest("build");
    let mut files = candidate_files();
    // Same length, one octet changed: only the digest differs.
    files[0].bytes = b"\x7fELF release binarY";
    let run = |keys: &TrustedKeySet,
               manifest_octets: Vec<u8>,
               record_octets: Vec<u8>,
               files: &[CandidateFile<'_>]| {
        verifier()
            .verify_signed_candidate(
                &manifest_octets,
                Some(&evidence),
                files,
                &record_octets,
                keys,
                NOW,
            )
            .map(|verified| verified.signatures.verified_key_ids)
    };
    let mut traversal = release.clone();
    traversal["files"][0]["path"] = json!("../secret");
    let mut short = sign(&a, &release);
    short.pop();

    let cases = [
        (
            "schema invalid and signature absent",
            run(&keys, octets(&traversal), record(&[]), &candidate_files()),
            ArtifactRefusal::ManifestSchemaInvalid,
        ),
        (
            "signature malformed and key unknown",
            run(
                &keys,
                octets(&release),
                record(&[(&unknown.id, short)]),
                &candidate_files(),
            ),
            ArtifactRefusal::SignatureMalformed,
        ),
        (
            "key unknown and file altered",
            run(
                &keys,
                octets(&release),
                record(&[(&unknown.id, sign(&unknown, &release))]),
                &files,
            ),
            ArtifactRefusal::SignatureKeyUnknown,
        ),
        (
            "key inactive and signature invalid",
            run(
                &revoked,
                octets(&release),
                record(&[(&a.id, sign(&a, &other))]),
                &candidate_files(),
            ),
            ArtifactRefusal::SignatureKeyNotActive,
        ),
        (
            "signature invalid and file digest wrong",
            run(
                &keys,
                octets(&release),
                record(&[(&a.id, sign(&a, &other))]),
                &files,
            ),
            ArtifactRefusal::SignatureInvalid,
        ),
        (
            "signature valid and file digest wrong",
            run(
                &keys,
                octets(&release),
                record(&[(&a.id, sign(&a, &release))]),
                &files,
            ),
            ArtifactRefusal::FileDigestMismatch,
        ),
    ];
    for (name, obtained, expected) in cases {
        println!("{name}: {obtained:?}");
        assert_eq!(obtained, Err(expected), "{name}");
    }
}

#[test]
fn a_tampered_file_is_refused_as_verify_candidate_refuses_it() {
    let a = test_key("artifact-verification-test-key-A");
    let keys = admit(vec![key_entry(
        &a.public,
        &["release"],
        "2026-01-01T00:00:00.000Z",
        None,
    )])
    .expect("keys");
    let (release, evidence) = manifest("release");
    let signatures = record(&[(&a.id, sign(&a, &release))]);
    let mut files = candidate_files();
    files[0].bytes = b"\x7fELF release binarY";

    let signed = verifier()
        .verify_signed_candidate(
            &octets(&release),
            Some(&evidence),
            &files,
            &signatures,
            &keys,
            NOW,
        )
        .map(|verified| verified.artifact);
    let unsigned = verifier().verify_candidate(&release, Some(&evidence), &files);
    assert_eq!(signed, Err(ArtifactRefusal::FileDigestMismatch));
    assert_eq!(signed, unsigned);
}

#[test]
fn a_signed_release_with_bound_evidence_is_accepted_against_its_pinned_key() {
    let pinned = test_key("artifact-verification-test-key-pinned");
    let dataset_only = test_key("artifact-verification-test-key-dataset");
    let keys = admit(vec![
        key_entry(
            &pinned.public,
            &["release"],
            "2026-01-01T00:00:00.000Z",
            None,
        ),
        key_entry(
            &dataset_only.public,
            &["dataset"],
            "2026-01-01T00:00:00.000Z",
            None,
        ),
    ])
    .expect("keys");
    let (release, evidence) = manifest("release");

    let verified = verifier()
        .verify_signed_candidate(
            &octets(&release),
            Some(&evidence),
            &candidate_files(),
            &record(&[(&pinned.id, sign(&pinned, &release))]),
            &keys,
            NOW,
        )
        .expect("signed release is verified");
    assert_eq!(verified.artifact, {
        verifier()
            .verify_candidate(&release, Some(&evidence), &candidate_files())
            .expect("unsigned verification")
    });
    assert_eq!(
        verified.signatures.verified_key_ids,
        vec![pinned.id.clone()]
    );
    assert_eq!(verified.signatures.ignored_unknown_key_ids, 0);

    let refused = verify_release(
        &keys,
        &release,
        &evidence,
        &[(&dataset_only.id, sign(&dataset_only, &release))],
    );
    assert_eq!(refused, Err(ArtifactRefusal::SignatureKeyNotAuthorized));

    // Evidence stays mandatory for a signed release.
    let missing_evidence = verifier()
        .verify_signed_candidate(
            &octets(&release),
            None,
            &candidate_files(),
            &record(&[(&pinned.id, sign(&pinned, &release))]),
            &keys,
            NOW,
        )
        .map(|_| ());
    assert_eq!(missing_evidence, Err(ArtifactRefusal::EvidenceRequired));
}

#[test]
fn bounds_are_the_contract_bounds() {
    assert_eq!(MAX_TRUSTED_KEYS, 64);
    assert_eq!(MAX_SIGNATURES, 16);
    assert_eq!(SIGNED_MESSAGE_DOMAIN, "libre-ai.artifact-manifest.v1");
}

#[test]
fn diagnostics_carry_no_signature_or_key_material() {
    let a = test_key("artifact-verification-test-key-A");
    let unknown = test_key("artifact-verification-test-key-unknown");
    let entry = key_entry(&a.public, &["release"], "2026-01-01T00:00:00.000Z", None);
    let pem_body = entry["publicKey"].as_str().expect("pem")[27..87].to_owned();
    let keys = admit(vec![entry]).expect("keys");
    let (release, evidence) = manifest("release");
    let (dataset, _) = manifest("dataset");
    let signature = sign(&a, &release);

    let refusals = [
        admit(vec![]).map(|_| ()),
        verify_release(&keys, &release, &evidence, &[]).map(|_| ()),
        verify_release(
            &keys,
            &release,
            &evidence,
            &[(&a.id, signature[1..].to_owned())],
        )
        .map(|_| ()),
        verify_release(
            &keys,
            &release,
            &evidence,
            &[(&unknown.id, signature.clone())],
        )
        .map(|_| ()),
        verifier()
            .verify_manifest_signatures(
                &octets(&release),
                &record(&[(&a.id, signature.clone())]),
                &keys,
                "2025-01-01T00:00:00.000Z",
            )
            .map(|_| ()),
        verifier()
            .verify_manifest_signatures(
                &octets(&dataset),
                &record(&[(&a.id, sign(&a, &dataset))]),
                &keys,
                NOW,
            )
            .map(|_| ()),
        verify_release(&keys, &release, &evidence, &[(&a.id, sign(&a, &dataset))]).map(|_| ()),
    ];
    let secrets = [
        signature.as_str(),
        &signature[..16],
        a.id.as_str(),
        &a.id[8..24],
        unknown.id.as_str(),
        pem_body.as_str(),
        &sha256_hex(&a.public)[..16],
    ];
    let mut codes = std::collections::BTreeSet::new();
    for refusal in refusals {
        let refusal = refusal.expect_err("each case is refused");
        codes.insert(refusal.code());
        let rendered = format!("{refusal:?} {}", refusal.code());
        for secret in secrets {
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }
    assert_eq!(codes.len(), 7, "each new refusal is exercised: {codes:?}");
    let rendered = format!("{keys:?}");
    for secret in secrets {
        assert!(!rendered.contains(secret), "{rendered}");
    }
}
