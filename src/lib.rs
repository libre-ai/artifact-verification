#![forbid(unsafe_code)]

mod digest;
mod model;
mod signature;
mod verify;

pub use digest::{artifact_content_digest, canonical_document_digest, sha256_hex};
pub use model::{ArtifactKind, ArtifactRefusal, CandidateFile, VerifiedArtifact, VerifiedEvidence};
pub use signature::{
    MAX_SIGNATURES, MAX_TRUSTED_KEYS, SIGNED_MESSAGE_DOMAIN, SignedVerifiedArtifact, TrustedKeySet,
    VerifiedSignatures, ed25519_point_is_admissible, ed25519_verify_strict,
    manifest_signed_message,
};
pub use verify::ArtifactVerifier;
