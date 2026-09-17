#[derive(Clone, Copy, Debug)]
pub struct CandidateFile<'a> {
    pub path: &'a str,
    pub media_type: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    Build,
    Dataset,
    Export,
    Release,
    Evidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEvidence {
    pub id: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    pub id: String,
    pub digest: String,
    pub kind: ArtifactKind,
    pub file_count: usize,
    pub evidence: Option<VerifiedEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRefusal {
    RegistryUnavailable,
    ManifestSchemaInvalid,
    EvidenceSchemaInvalid,
    CandidateEmpty,
    CandidateTooLarge,
    CandidatePathInvalid,
    CandidateMediaTypeInvalid,
    DuplicatePath,
    FileSetMismatch,
    FileSizeMismatch,
    FileDigestMismatch,
    FileMediaTypeMismatch,
    ManifestDigestMismatch,
    EvidenceRequired,
    EvidenceReferenceMismatch,
    EvidenceNotPassing,
    EvidenceSubjectMismatch,
    CanonicalizationFailed,
}

impl ArtifactRefusal {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RegistryUnavailable => "artifact.registry-unavailable",
            Self::ManifestSchemaInvalid => "artifact.manifest-schema-invalid",
            Self::EvidenceSchemaInvalid => "artifact.evidence-schema-invalid",
            Self::CandidateEmpty => "artifact.candidate-empty",
            Self::CandidateTooLarge => "artifact.candidate-too-large",
            Self::CandidatePathInvalid => "artifact.candidate-path-invalid",
            Self::CandidateMediaTypeInvalid => "artifact.candidate-media-type-invalid",
            Self::DuplicatePath => "artifact.path-duplicate",
            Self::FileSetMismatch => "artifact.file-set-mismatch",
            Self::FileSizeMismatch => "artifact.file-size-mismatch",
            Self::FileDigestMismatch => "artifact.file-digest-mismatch",
            Self::FileMediaTypeMismatch => "artifact.file-media-type-mismatch",
            Self::ManifestDigestMismatch => "artifact.manifest-digest-mismatch",
            Self::EvidenceRequired => "artifact.evidence-required",
            Self::EvidenceReferenceMismatch => "artifact.evidence-reference-mismatch",
            Self::EvidenceNotPassing => "artifact.evidence-not-passing",
            Self::EvidenceSubjectMismatch => "artifact.evidence-subject-mismatch",
            Self::CanonicalizationFailed => "artifact.canonicalization-failed",
        }
    }
}
