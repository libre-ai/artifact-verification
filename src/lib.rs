//! Artifact verification: candidate files against `artifact-manifest.v1`, and
//! detached Ed25519 signatures over the manifest octets.
//!
//! The signed-message builder hashes a parsed value and the strict primitive skips the
//! registry: neither is public, so a caller cannot sign or check a value read by
//! another parser (S0). Both lines below must fail to compile.
//!
//! ```compile_fail
//! let _ = libre_ai_artifact::manifest_signed_message;
//! ```
//!
//! ```compile_fail
//! let _ = libre_ai_artifact::ed25519_verify_strict;
//! ```

#![forbid(unsafe_code)]

mod digest;
mod model;
mod signature;
mod verify;

pub use digest::{artifact_content_digest, canonical_document_digest, sha256_hex};
pub use model::{ArtifactKind, ArtifactRefusal, CandidateFile, VerifiedArtifact, VerifiedEvidence};
pub use signature::{
    MAX_SIGNATURES, MAX_TRUSTED_KEYS, SIGNED_MESSAGE_DOMAIN, SignedVerifiedArtifact, TrustedKeySet,
    VerifiedSignatures, ed25519_point_is_admissible,
};
pub use verify::ArtifactVerifier;
