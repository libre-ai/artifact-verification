//! Detached Ed25519 signatures over an `artifact-manifest.v1` document.
//!
//! Projection of the candidate contracts `artifact-manifest-signatures.v1` and
//! `signing-keys.v1` of `libre-ai/schemas-and-contracts`
//! (`contracts/artifact-manifest-signatures-v1/SEMANTICS.md`). The rule identifiers
//! below (`K0`..`K6`, `S0`..`S10`) are the contract's. The contract is the authority:
//! nothing here defines a wire form.
//!
//! The crate reads no file, no clock and no network: the caller loads the registry
//! octets it trusts, reads `now` from a trusted clock and passes both in.

use crate::verify::{ArtifactVerifier, artifact_kind};
use crate::{ArtifactKind, ArtifactRefusal, sha256_hex};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{Signature, VerifyingKey};
use libre_ai_contract_types::generated::artifact_manifest_signatures_v1::LibreAiArtifactManifestSignaturesV1;
use libre_ai_contract_types::generated::artifact_manifest_v1::LibreAiArtifactManifestV1;
use libre_ai_contract_types::generated::signing_keys_v1::{
    Instant, LibreAiSigningKeysV1, LibreAiSigningKeysV1KeysItem,
    LibreAiSigningKeysV1KeysItemArtifactTypesItem,
};
use libre_ai_contract_types::strict_json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

/// Upper bound of a registry (K1).
pub const MAX_TRUSTED_KEYS: usize = 64;
/// Upper bound of a signature record (S1).
pub const MAX_SIGNATURES: usize = 16;
/// Domain of the signed message (S4): the `schemaVersion` of `artifact-manifest.v1`.
pub const SIGNED_MESSAGE_DOMAIN: &str = "libre-ai.artifact-manifest.v1";

const REGISTRY_SCHEMA: &str = "signing-keys.v1.schema.json";
const RECORD_SCHEMA: &str = "artifact-manifest-signatures.v1.schema.json";
const KEY_ID_PREFIX: &str = "ed25519-";
const PEM_PREFIX: &str = "-----BEGIN PUBLIC KEY-----\n";
const PEM_SUFFIX: &str = "\n-----END PUBLIC KEY-----";
/// DER prefix of an Ed25519 SubjectPublicKeyInfo (OID 1.3.101.112), before the 32 key octets.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const SIGNATURE_LENGTH: usize = 64;
const POINT_LENGTH: usize = 32;

/// One admitted registry key. Its fields never leave the crate: a refusal carries
/// a code only (K7).
struct TrustedKey {
    verifying_key: VerifyingKey,
    artifact_kinds: Vec<ArtifactKind>,
    activated_at: Instant,
    revoked_at: Option<Instant>,
}

/// A `signing-keys.v1` registry that passed every rule K0 to K6, immutable.
///
/// Built only by [`ArtifactVerifier::admit_signing_keys`]: a registry that breaks a
/// rule yields no set, so no signature can ever be read against it.
pub struct TrustedKeySet {
    keys: BTreeMap<String, TrustedKey>,
}

impl TrustedKeySet {
    /// Number of admitted keys, between 1 and [`MAX_TRUSTED_KEYS`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Always false for an admitted set (K1 requires at least one key).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl Debug for TrustedKeySet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        // Count only: no registry member is copied into a diagnostic (K7).
        formatter
            .debug_struct("TrustedKeySet")
            .field("len", &self.keys.len())
            .finish_non_exhaustive()
    }
}

/// Outcome of an accepted signature record (S10).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSignatures {
    /// Identifiers of the registry keys whose signature verified, ascending.
    pub verified_key_ids: Vec<String>,
    /// Signatures naming an identifier absent from the registry (S5).
    pub ignored_unknown_key_ids: usize,
}

/// Outcome of [`ArtifactVerifier::verify_signed_candidate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedVerifiedArtifact {
    pub artifact: crate::VerifiedArtifact,
    pub signatures: VerifiedSignatures,
}

/// Strict Ed25519 point profile (K2, and R in S8): 32 octets that decode to a point
/// of the curve, re-encode to the same octets (canonical `y`, no negative zero), are
/// not the identity and lie in the prime-order subgroup.
#[must_use]
pub fn ed25519_point_is_admissible(encoded: &[u8]) -> bool {
    let Ok(octets) = <[u8; POINT_LENGTH]>::try_from(encoded) else {
        return false;
    };
    let Some(point) = CompressedEdwardsY(octets).decompress() else {
        return false;
    };
    point.compress().to_bytes() == octets && !point.is_identity() && point.is_torsion_free()
}

/// Strict Ed25519 verification (S8): `A` and `R` admissible, `S < L`, then the
/// equation. The checks on `A`, `R` and `S` run here, before the library, whatever
/// the library does by default (SEMANTICS S8).
#[must_use]
pub fn ed25519_verify_strict(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public_key), Ok(signature)) = (
        <[u8; POINT_LENGTH]>::try_from(public_key),
        <[u8; SIGNATURE_LENGTH]>::try_from(signature),
    ) else {
        return false;
    };
    if !ed25519_point_is_admissible(&public_key) {
        return false;
    }
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    signature_verifies(&verifying_key, message, &signature)
}

fn signature_verifies(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &[u8; SIGNATURE_LENGTH],
) -> bool {
    let (r_octets, s_octets) = signature.split_at(POINT_LENGTH);
    let Ok(s_octets) = <[u8; POINT_LENGTH]>::try_from(s_octets) else {
        return false;
    };
    if !ed25519_point_is_admissible(r_octets) {
        return false;
    }
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(s_octets)).is_none() {
        return false;
    }
    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// The signed message of S4:
/// `UTF8(manifest.schemaVersion) || 0x00 || SHA-256(RFC 8785(manifest))`.
///
/// The manifest is the value read from its octets by the strict reader (S0).
pub fn manifest_signed_message(manifest_document: &Value) -> Result<Vec<u8>, ArtifactRefusal> {
    let domain = manifest_document
        .get("schemaVersion")
        .and_then(Value::as_str)
        .ok_or(ArtifactRefusal::ManifestSchemaInvalid)?;
    let canonical = strict_json::canonicalize(manifest_document)
        .map_err(|_| ArtifactRefusal::CanonicalizationFailed)?;
    let mut message = Vec::with_capacity(domain.len() + 1 + 32);
    message.extend_from_slice(domain.as_bytes());
    message.push(0x00);
    message.extend_from_slice(&Sha256::digest(&canonical));
    Ok(message)
}

/// Admits a `signing-keys.v1` registry from its received octets (K0 to K6).
pub(crate) fn admit_signing_keys(
    verifier: &ArtifactVerifier,
    registry_octets: &[u8],
) -> Result<TrustedKeySet, ArtifactRefusal> {
    // K0: octets first, before any member is read.
    let document =
        strict_json::parse(registry_octets).map_err(|_| ArtifactRefusal::KeySetInvalid)?;
    // K1: closed schema (bounds, forms, revocation members).
    verifier.validate_schema(REGISTRY_SCHEMA, &document, ArtifactRefusal::KeySetInvalid)?;
    let registry: LibreAiSigningKeysV1 =
        serde_json::from_value(document).map_err(|_| ArtifactRefusal::KeySetInvalid)?;
    if registry.keys.is_empty() || registry.keys.len() > MAX_TRUSTED_KEYS {
        return Err(ArtifactRefusal::KeySetInvalid);
    }

    let mut keys = BTreeMap::new();
    for entry in &registry.keys {
        let (identifier, key) = admit_key(entry)?;
        // K4: unique identifier; with K3 this also refuses one key under two entries.
        if keys.insert(identifier, key).is_some() {
            return Err(ArtifactRefusal::KeySetInvalid);
        }
    }
    Ok(TrustedKeySet { keys })
}

fn admit_key(
    entry: &LibreAiSigningKeysV1KeysItem,
) -> Result<(String, TrustedKey), ArtifactRefusal> {
    // K1: the exact PEM SPKI Ed25519 form.
    let public_key = spki_pem_public_key(entry.public_key.as_str())?;
    // K2: strict point profile.
    if !ed25519_point_is_admissible(&public_key) {
        return Err(ArtifactRefusal::KeySetInvalid);
    }
    // K3: the identifier is recomputed from the 32 raw octets, never trusted.
    let identifier = format!("{KEY_ID_PREFIX}{}", sha256_hex(&public_key));
    if entry.signing_key_id.as_str() != identifier {
        return Err(ArtifactRefusal::KeySetInvalid);
    }
    let activated_at = Instant(entry.activated_at);
    let revoked_at = entry.revoked_at.map(Instant);
    if let Some(revoked_at) = &revoked_at {
        // K5: half-open window with a strictly later end.
        if revoked_at.0 <= activated_at.0 {
            return Err(ArtifactRefusal::KeySetInvalid);
        }
        // K6: reason and witness present, revocation not after discovery.
        let (Some(_), Some(witness)) = (&entry.revocation_reason, &entry.revocation_witness) else {
            return Err(ArtifactRefusal::KeySetInvalid);
        };
        if revoked_at.0 > witness.discovered_at {
            return Err(ArtifactRefusal::KeySetInvalid);
        }
    }
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| ArtifactRefusal::KeySetInvalid)?;
    let artifact_kinds = entry
        .artifact_types
        .iter()
        .map(|kind| registry_artifact_kind(*kind))
        .collect();
    Ok((
        identifier,
        TrustedKey {
            verifying_key,
            artifact_kinds,
            activated_at,
            revoked_at,
        },
    ))
}

fn registry_artifact_kind(kind: LibreAiSigningKeysV1KeysItemArtifactTypesItem) -> ArtifactKind {
    match kind {
        LibreAiSigningKeysV1KeysItemArtifactTypesItem::Build => ArtifactKind::Build,
        LibreAiSigningKeysV1KeysItemArtifactTypesItem::Dataset => ArtifactKind::Dataset,
        LibreAiSigningKeysV1KeysItemArtifactTypesItem::Export => ArtifactKind::Export,
        LibreAiSigningKeysV1KeysItemArtifactTypesItem::Release => ArtifactKind::Release,
        LibreAiSigningKeysV1KeysItemArtifactTypesItem::Evidence => ArtifactKind::Evidence,
    }
}

/// The 32 key octets of the exact PEM form of the contract, or `KeySetInvalid`.
fn spki_pem_public_key(pem: &str) -> Result<[u8; POINT_LENGTH], ArtifactRefusal> {
    let body = pem
        .strip_prefix(PEM_PREFIX)
        .and_then(|rest| rest.strip_suffix(PEM_SUFFIX))
        .ok_or(ArtifactRefusal::KeySetInvalid)?;
    // 60 characters: 59 of data and one `=` for the 44-octet DER.
    let data = body
        .strip_suffix('=')
        .filter(|data| data.len() == 59 && !data.ends_with('='))
        .ok_or(ArtifactRefusal::KeySetInvalid)?;
    let der = decode_base64(data.as_bytes(), Base64Alphabet::Standard)
        .ok_or(ArtifactRefusal::KeySetInvalid)?;
    let key = der
        .strip_prefix(&SPKI_ED25519_PREFIX)
        .ok_or(ArtifactRefusal::KeySetInvalid)?;
    <[u8; POINT_LENGTH]>::try_from(key).map_err(|_| ArtifactRefusal::KeySetInvalid)
}

struct RecordSignature {
    signing_key_id: String,
    octets: [u8; SIGNATURE_LENGTH],
}

/// Verifies a detached signature record over a manifest (S0 to S10), and returns the
/// manifest value read from its octets with the outcome.
pub(crate) fn verify_manifest_signatures(
    verifier: &ArtifactVerifier,
    manifest_octets: &[u8],
    record_octets: &[u8],
    keys: &TrustedKeySet,
    now: &str,
) -> Result<(Value, VerifiedSignatures), ArtifactRefusal> {
    // S0 (manifest octets), then S3.
    let manifest_document =
        strict_json::parse(manifest_octets).map_err(|_| ArtifactRefusal::ManifestSchemaInvalid)?;
    verifier.validate_manifest_schema(&manifest_document)?;
    let manifest: LibreAiArtifactManifestV1 = serde_json::from_value(manifest_document.clone())
        .map_err(|_| ArtifactRefusal::ManifestSchemaInvalid)?;
    let manifest_kind = artifact_kind(manifest.artifact_type);

    // S0 (record octets), S1, S2.
    let signatures = read_record(verifier, record_octets)?;

    // S5: select keys in the registry only; unknown identifiers are counted.
    let mut selected = Vec::with_capacity(signatures.len());
    let mut ignored_unknown_key_ids = 0_usize;
    for signature in &signatures {
        match keys.keys.get(&signature.signing_key_id) {
            Some(key) => selected.push((signature, key)),
            None => ignored_unknown_key_ids += 1,
        }
    }
    if selected.is_empty() {
        return Err(ArtifactRefusal::SignatureKeyUnknown);
    }

    // S6 over every registry-key signature. A `now` outside the fixed form
    // establishes no instant and is refused like an inactive key.
    let now = parse_instant(now).ok_or(ArtifactRefusal::SignatureKeyNotActive)?;
    if selected.iter().any(|(_, key)| !key_is_active(key, &now)) {
        return Err(ArtifactRefusal::SignatureKeyNotActive);
    }
    // S7 over every registry-key signature.
    if selected
        .iter()
        .any(|(_, key)| !key.artifact_kinds.contains(&manifest_kind))
    {
        return Err(ArtifactRefusal::SignatureKeyNotAuthorized);
    }
    // S4, S8, S9: every registry-key signature verifies; none is skipped.
    let message = manifest_signed_message(&manifest_document)?;
    if selected.iter().any(|(signature, key)| {
        !signature_verifies(&key.verifying_key, &message, &signature.octets)
    }) {
        return Err(ArtifactRefusal::SignatureInvalid);
    }

    let verified_key_ids = selected
        .iter()
        .map(|(signature, _)| signature.signing_key_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok((
        manifest_document,
        VerifiedSignatures {
            verified_key_ids,
            ignored_unknown_key_ids,
        },
    ))
}

fn read_record(
    verifier: &ArtifactVerifier,
    record_octets: &[u8],
) -> Result<Vec<RecordSignature>, ArtifactRefusal> {
    let document =
        strict_json::parse(record_octets).map_err(|_| ArtifactRefusal::SignatureMalformed)?;
    let issues = verifier.schema_issues(RECORD_SCHEMA, &document)?;
    if !issues.is_empty() {
        // An empty list is its own refusal only when it is the record's sole defect.
        let only_empty_list = issues
            .iter()
            .all(|issue| issue.instance_path == "/signatures" && issue.keyword == "minItems")
            && document
                .get("signatures")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty);
        return Err(if only_empty_list {
            ArtifactRefusal::SignatureRequired
        } else {
            ArtifactRefusal::SignatureMalformed
        });
    }
    let record: LibreAiArtifactManifestSignaturesV1 =
        serde_json::from_value(document).map_err(|_| ArtifactRefusal::SignatureMalformed)?;
    if record.signatures.is_empty() {
        return Err(ArtifactRefusal::SignatureRequired);
    }
    if record.signatures.len() > MAX_SIGNATURES {
        return Err(ArtifactRefusal::SignatureMalformed);
    }

    let mut identifiers = BTreeSet::new();
    let mut signatures = Vec::with_capacity(record.signatures.len());
    for item in &record.signatures {
        let signing_key_id = item.signing_key_id.as_str().to_owned();
        // S2: one key signs a manifest at most once.
        if !identifiers.insert(signing_key_id.clone()) {
            return Err(ArtifactRefusal::SignatureMalformed);
        }
        let octets = decode_base64(item.signature.as_bytes(), Base64Alphabet::Url)
            .and_then(|octets| <[u8; SIGNATURE_LENGTH]>::try_from(octets).ok())
            .ok_or(ArtifactRefusal::SignatureMalformed)?;
        signatures.push(RecordSignature {
            signing_key_id,
            octets,
        });
    }
    Ok(signatures)
}

fn key_is_active(key: &TrustedKey, now: &Instant) -> bool {
    key.activated_at.0 <= now.0 && key.revoked_at.as_ref().is_none_or(|end| now.0 < end.0)
}

/// Reads an instant of the contract's fixed form `YYYY-MM-DDTHH:MM:SS.sssZ`, a real
/// calendar instant (no hour 24, no 30 February, no second 60), or nothing.
fn parse_instant(text: &str) -> Option<Instant> {
    if !fixed_form_instant_is_valid(text) {
        return None;
    }
    serde_json::from_value(Value::String(text.to_owned())).ok()
}

fn fixed_form_instant_is_valid(text: &str) -> bool {
    const SHAPE: &[u8; 24] = b"dddd-dd-ddTdd:dd:dd.dddZ";
    let bytes = text.as_bytes();
    if bytes.len() != SHAPE.len()
        || !bytes.iter().zip(SHAPE).all(|(byte, shape)| match shape {
            b'd' => byte.is_ascii_digit(),
            literal => byte == literal,
        })
    {
        return false;
    }
    let number = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .unwrap_or_default()
            .iter()
            .fold(0_u32, |value, digit| value * 10 + u32::from(digit - b'0'))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let (hour, minute, second) = (number(11..13), number(14..16), number(17..19));
    (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
        && hour < 24
        && minute < 60
        && second < 60
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[derive(Clone, Copy)]
enum Base64Alphabet {
    Standard,
    Url,
}

/// Decodes unpadded Base64 and refuses any non-canonical text: a character outside
/// the alphabet, a length that leaves 6 bits, or non-zero unused bits.
fn decode_base64(text: &[u8], alphabet: Base64Alphabet) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut output = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for character in text {
        let value = match (character, alphabet) {
            (b'A'..=b'Z', _) => character - b'A',
            (b'a'..=b'z', _) => character - b'a' + 26,
            (b'0'..=b'9', _) => character - b'0' + 52,
            (b'+', Base64Alphabet::Standard) | (b'-', Base64Alphabet::Url) => 62,
            (b'/', Base64Alphabet::Standard) | (b'_', Base64Alphabet::Url) => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    (buffer == 0).then_some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_refuses_non_canonical_text() {
        assert_eq!(decode_base64(b"AQ", Base64Alphabet::Url), Some(vec![0x01]));
        assert_eq!(decode_base64(b"AR", Base64Alphabet::Url), None);
        assert_eq!(decode_base64(b"A", Base64Alphabet::Url), None);
        assert_eq!(decode_base64(b"+/", Base64Alphabet::Url), None);
        assert_eq!(decode_base64(b"-_", Base64Alphabet::Standard), None);
        assert_eq!(
            decode_base64(b"-_8", Base64Alphabet::Url),
            Some(vec![0xfb, 0xff])
        );
        assert_eq!(
            decode_base64(b"+/8", Base64Alphabet::Standard),
            Some(vec![0xfb, 0xff])
        );
    }

    #[test]
    fn fixed_form_instants_are_real_calendar_instants() {
        for valid in [
            "2026-10-15T12:00:00.000Z",
            "2024-02-29T23:59:59.999Z",
            "2000-02-29T00:00:00.000Z",
            "2026-04-30T00:00:00.000Z",
        ] {
            assert!(parse_instant(valid).is_some(), "{valid}");
        }
        for invalid in [
            "2026-10-15T24:00:00.000Z",
            "2026-02-30T12:00:00.000Z",
            "2100-02-29T12:00:00.000Z",
            "2026-04-31T12:00:00.000Z",
            "2026-13-01T12:00:00.000Z",
            "2026-00-01T12:00:00.000Z",
            "2026-01-00T12:00:00.000Z",
            "2026-10-15T12:60:00.000Z",
            "2026-10-15T12:00:60.000Z",
            "2026-10-15T12:00:00Z",
            "2026-10-15T12:00:00.000+00:00",
            "2026-10-15t12:00:00.000Z",
            "",
        ] {
            assert!(parse_instant(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn pem_refuses_every_other_form() {
        let good = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAhamztDTfbxrKnWku/l8y6nWLZ/T0P6SO8wZaR98+OOw=\n-----END PUBLIC KEY-----";
        assert!(spki_pem_public_key(good).is_ok());
        for bad in [
            format!("{good}\n"),
            good.replace("OOw=", "OOx="),
            good.replace("MCowBQYDK2VwAyEA", "MCowBQYDK2VuAyEA"),
            good.replace("8wZaR98+OOw=", "8wZaR98+OO=="),
            good.replace("BEGIN PUBLIC KEY-----\n", "BEGIN PUBLIC KEY-----\r\n"),
        ] {
            assert_eq!(
                spki_pem_public_key(&bad).map(|_| ()),
                Err(ArtifactRefusal::KeySetInvalid)
            );
        }
    }

    #[test]
    fn primitive_refuses_wrong_lengths() {
        assert!(!ed25519_point_is_admissible(&[0_u8; 31]));
        assert!(!ed25519_verify_strict(&[0_u8; 31], b"", &[0_u8; 64]));
        assert!(!ed25519_verify_strict(&[0_u8; 32], b"", &[0_u8; 63]));
    }
}
