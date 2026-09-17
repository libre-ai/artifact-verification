#![forbid(unsafe_code)]

mod digest;
mod model;
mod verify;

pub use digest::{artifact_content_digest, canonical_document_digest, sha256_hex};
pub use model::{ArtifactKind, ArtifactRefusal, CandidateFile, VerifiedArtifact, VerifiedEvidence};
pub use verify::ArtifactVerifier;
