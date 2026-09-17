use crate::digest::{ContentDescriptor, content_descriptors, descriptor_set_digest};
use crate::{
    ArtifactKind, ArtifactRefusal, CandidateFile, VerifiedArtifact, VerifiedEvidence,
    canonical_document_digest,
};
use libre_ai_contract_types::ContractRegistry;
use libre_ai_contract_types::generated::artifact_manifest_v1::{
    LibreAiArtifactManifestV1, LibreAiArtifactManifestV1ArtifactType,
};
use libre_ai_contract_types::generated::evidence_report_v1::{
    LibreAiEvidenceReportV1, LibreAiEvidenceReportV1Status,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MANIFEST_SCHEMA: &str = "artifact-manifest.v1.schema.json";
const EVIDENCE_SCHEMA: &str = "evidence-report.v1.schema.json";
const EVIDENCE_MEDIA_TYPE: &str = "application/json";

pub struct ArtifactVerifier {
    registry: ContractRegistry,
}

impl ArtifactVerifier {
    pub fn embedded() -> Result<Self, ArtifactRefusal> {
        ContractRegistry::embedded()
            .map(|registry| Self { registry })
            .map_err(|_| ArtifactRefusal::RegistryUnavailable)
    }

    pub fn verify_candidate(
        &self,
        manifest_document: &Value,
        evidence_document: Option<&Value>,
        files: &[CandidateFile<'_>],
    ) -> Result<VerifiedArtifact, ArtifactRefusal> {
        self.validate_schema(
            MANIFEST_SCHEMA,
            manifest_document,
            ArtifactRefusal::ManifestSchemaInvalid,
        )?;
        let manifest: LibreAiArtifactManifestV1 = serde_json::from_value(manifest_document.clone())
            .map_err(|_| ArtifactRefusal::ManifestSchemaInvalid)?;

        let descriptors = content_descriptors(files)?;
        verify_file_set(&manifest, &descriptors)?;
        let content_digest = descriptor_set_digest(&descriptors)?;
        if manifest.digest.as_str() != content_digest {
            return Err(ArtifactRefusal::ManifestDigestMismatch);
        }

        let kind = artifact_kind(manifest.artifact_type);
        let evidence =
            self.verify_evidence_binding(&manifest, kind, evidence_document, &content_digest)?;

        Ok(VerifiedArtifact {
            id: manifest.id.as_str().to_owned(),
            digest: content_digest,
            kind,
            file_count: files.len(),
            evidence,
        })
    }

    fn verify_evidence_binding(
        &self,
        manifest: &LibreAiArtifactManifestV1,
        kind: ArtifactKind,
        evidence_document: Option<&Value>,
        content_digest: &str,
    ) -> Result<Option<VerifiedEvidence>, ArtifactRefusal> {
        let required = matches!(kind, ArtifactKind::Build | ArtifactKind::Release);
        let Some(reference) = manifest.evidence_report.as_ref() else {
            return if required {
                Err(ArtifactRefusal::EvidenceRequired)
            } else if evidence_document.is_some() {
                Err(ArtifactRefusal::EvidenceReferenceMismatch)
            } else {
                Ok(None)
            };
        };
        let Some(evidence_document) = evidence_document else {
            return Err(ArtifactRefusal::EvidenceRequired);
        };

        self.validate_schema(
            EVIDENCE_SCHEMA,
            evidence_document,
            ArtifactRefusal::EvidenceSchemaInvalid,
        )?;
        let evidence: LibreAiEvidenceReportV1 =
            serde_json::from_value(evidence_document.clone())
                .map_err(|_| ArtifactRefusal::EvidenceSchemaInvalid)?;
        if evidence.status != LibreAiEvidenceReportV1Status::Pass {
            return Err(ArtifactRefusal::EvidenceNotPassing);
        }

        let evidence_digest = canonical_document_digest(evidence_document)?;
        if reference.id.as_str() != evidence.id.as_str()
            || reference.digest.as_str() != evidence_digest
            || reference.media_type.as_str() != EVIDENCE_MEDIA_TYPE
        {
            return Err(ArtifactRefusal::EvidenceReferenceMismatch);
        }
        if evidence.subject.as_str() != manifest.id.as_str()
            || evidence.subject_digest.as_str() != content_digest
        {
            return Err(ArtifactRefusal::EvidenceSubjectMismatch);
        }

        Ok(Some(VerifiedEvidence {
            id: evidence.id.as_str().to_owned(),
            digest: evidence_digest,
        }))
    }

    fn validate_schema(
        &self,
        schema: &str,
        document: &Value,
        refusal: ArtifactRefusal,
    ) -> Result<(), ArtifactRefusal> {
        match self.registry.validate(schema, document) {
            Ok(issues) if issues.is_empty() => Ok(()),
            Ok(_) => Err(refusal),
            Err(_) => Err(ArtifactRefusal::RegistryUnavailable),
        }
    }
}

fn artifact_kind(kind: LibreAiArtifactManifestV1ArtifactType) -> ArtifactKind {
    match kind {
        LibreAiArtifactManifestV1ArtifactType::Build => ArtifactKind::Build,
        LibreAiArtifactManifestV1ArtifactType::Dataset => ArtifactKind::Dataset,
        LibreAiArtifactManifestV1ArtifactType::Export => ArtifactKind::Export,
        LibreAiArtifactManifestV1ArtifactType::Release => ArtifactKind::Release,
        LibreAiArtifactManifestV1ArtifactType::Evidence => ArtifactKind::Evidence,
    }
}

fn verify_file_set(
    manifest: &LibreAiArtifactManifestV1,
    descriptors: &[ContentDescriptor<'_>],
) -> Result<(), ArtifactRefusal> {
    let candidates = descriptors
        .iter()
        .map(|descriptor| (descriptor.path, descriptor))
        .collect::<BTreeMap<_, _>>();
    if candidates.len() != descriptors.len() || manifest.files.len() != descriptors.len() {
        return Err(ArtifactRefusal::FileSetMismatch);
    }

    let mut manifest_paths = BTreeSet::new();
    for entry in &manifest.files {
        let path = entry.path.as_str();
        if !manifest_paths.insert(path) {
            return Err(ArtifactRefusal::DuplicatePath);
        }
        let Some(candidate) = candidates.get(path) else {
            return Err(ArtifactRefusal::FileSetMismatch);
        };
        let size = i64::try_from(candidate.size).map_err(|_| ArtifactRefusal::CandidateTooLarge)?;
        if entry.size != size {
            return Err(ArtifactRefusal::FileSizeMismatch);
        }
        if entry.digest.as_str() != candidate.digest {
            return Err(ArtifactRefusal::FileDigestMismatch);
        }
        if entry.media_type.as_str() != candidate.media_type {
            return Err(ArtifactRefusal::FileMediaTypeMismatch);
        }
    }
    Ok(())
}
