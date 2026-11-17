//! Contract-vector tests of the crate-private signature primitives.
//!
//! The vectors are read from the schemas-and-contracts revision that Cargo compiled
//! (located by `cargo metadata`), never copied here. A declared fixture that cannot
//! be read fails the test, never skips it.

use super::{
    Base64Alphabet, POINT_LENGTH, SIGNATURE_LENGTH, decode_base64, ed25519_point_is_admissible,
    manifest_signed_message, signature_encoding_is_admissible, signature_verifies,
};
use ed25519_dalek::VerifyingKey;
use libre_ai_contract_types::strict_json;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const SIGNATURE_VECTORS: &str = "contracts/fixtures/artifact-manifest-signatures-v1/vectors.json";
const STRICT_VECTORS: &str = "contracts/fixtures/build-brief-v2/strict-ed25519-vectors.json";

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
    metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "libre-ai-contract-types")
        .expect("libre-ai-contract-types is a dependency")
        .clone()
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

fn b64url(text: &Value) -> Vec<u8> {
    let text = text.as_str().expect("Base64url text");
    decode_base64(text.as_bytes(), Base64Alphabet::Url).expect("canonical Base64url")
}

fn signature_octets(text: &Value) -> [u8; SIGNATURE_LENGTH] {
    <[u8; SIGNATURE_LENGTH]>::try_from(b64url(text)).expect("64 signature octets")
}

/// The raw strict primitive (S8): `A` admissible, then the signature checks and the
/// equation, exactly as the crate composes them for an admitted key.
fn verify_strict(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        <[u8; POINT_LENGTH]>::try_from(public_key),
        <[u8; SIGNATURE_LENGTH]>::try_from(signature),
    ) else {
        return false;
    };
    if !ed25519_point_is_admissible(&public_key) {
        return false;
    }
    VerifyingKey::from_bytes(&public_key)
        .is_ok_and(|key| signature_verifies(&key, message, &signature))
}

#[test]
fn primitive_refuses_wrong_lengths() {
    assert!(!verify_strict(&[0_u8; 31], b"", &[0_u8; 64]));
    assert!(!verify_strict(&[0_u8; 32], b"", &[0_u8; 63]));
}

#[test]
fn strict_signature_vectors_match_the_primitive() {
    let vectors = contract_fixture(STRICT_VECTORS);
    let signatures = vectors["signatures"].as_array().expect("signatures");
    let mut accepted_count = 0_usize;
    let mut failures = Vec::new();
    for vector in signatures {
        let obtained = verify_strict(
            &b64url(&vector["publicKey"]),
            &b64url(&vector["message"]),
            &b64url(&vector["signature"]),
        );
        accepted_count += usize::from(obtained);
        if obtained != vector["accepted"].as_bool().expect("accepted") {
            failures.push(vector["id"].as_str().expect("id").to_owned());
        }
    }
    println!(
        "signatures read {}, accepted {accepted_count}",
        signatures.len()
    );
    assert!(failures.is_empty(), "signatures: {failures:?}");
    assert_eq!(signatures.len(), 51);
    assert_eq!(accepted_count, 2);
}

/// S8 asks the consumer itself for `R` admissible and `S < L`, whatever the library.
/// These vectors reach the pure checks directly, without ed25519-dalek.
#[test]
fn signature_encoding_checks_refuse_every_r_and_s_vector() {
    let contract = contract_fixture(SIGNATURE_VECTORS);
    let strict = contract_fixture(STRICT_VECTORS);
    let mut counts = [0_usize; 4];
    let mut failures = Vec::new();

    for vector in contract["signatureVectors"].as_array().expect("vectors") {
        let id = vector["id"].as_str().expect("id");
        let family = if id.starts_with("r-") {
            0
        } else if id == "s-not-reduced" {
            1
        } else {
            continue;
        };
        for item in vector["record"]["signatures"].as_array().expect("record") {
            counts[family] += 1;
            if signature_encoding_is_admissible(&signature_octets(&item["signature"])) {
                failures.push(id.to_owned());
            }
        }
    }
    for vector in strict["signatures"].as_array().expect("signatures") {
        let id = vector["id"].as_str().expect("id");
        let family = if id.starts_with("r-") {
            2
        } else if id.starts_with("scalar-") {
            3
        } else {
            continue;
        };
        counts[family] += 1;
        if signature_encoding_is_admissible(&signature_octets(&vector["signature"])) {
            failures.push(id.to_owned());
        }
    }
    println!(
        "contract r-* {}, contract s-not-reduced {}, strict r-* {}, strict scalar-* {}, admitted {}",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        failures.len()
    );
    assert!(failures.is_empty(), "admitted: {failures:?}");
    assert_eq!(counts, [16, 1, 19, 5]);
}

/// Control: the same checks admit every signature that the contract accepts, so the
/// refusals above are not a constant `false`.
#[test]
fn signature_encoding_checks_admit_every_accepted_signature() {
    let contract = contract_fixture(SIGNATURE_VECTORS);
    let mut admitted = 0_usize;
    let mut failures = Vec::new();
    for vector in contract["signatureVectors"].as_array().expect("vectors") {
        if vector["expected"]["outcome"] != "accepted" {
            continue;
        }
        let verified = vector["expected"]["verifiedKeyIds"]
            .as_array()
            .expect("verified ids");
        for item in vector["record"]["signatures"].as_array().expect("record") {
            if !verified.contains(&item["signingKeyId"]) {
                continue;
            }
            if signature_encoding_is_admissible(&signature_octets(&item["signature"])) {
                admitted += 1;
            } else {
                failures.push(vector["id"].as_str().expect("id").to_owned());
            }
        }
    }
    println!("accepted signatures admitted {admitted}");
    assert!(failures.is_empty(), "refused: {failures:?}");
    assert!(admitted > 0);
}

#[test]
fn published_messages_match_the_crate_message() {
    let vectors = contract_fixture(SIGNATURE_VECTORS);
    let messages = vectors["messages"].as_object().expect("messages");
    let mut failures = Vec::new();
    for (name, expected) in messages {
        let manifest_octets = b64url(&vectors["manifestOctets"][name]);
        let manifest = strict_json::parse(&manifest_octets).expect("strict manifest");
        let built = manifest_signed_message(&manifest).expect("message");
        if built != b64url(expected) {
            failures.push(name.clone());
        }
    }
    println!(
        "messages read {}, failures {}",
        messages.len(),
        failures.len()
    );
    assert!(!messages.is_empty());
    assert!(failures.is_empty(), "messages: {failures:?}");
}
