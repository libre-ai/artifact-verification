use libre_ai_artifact::{
    ArtifactKind, ArtifactRefusal, ArtifactVerifier, CandidateFile, artifact_content_digest,
    canonical_document_digest, sha256_hex,
};
use serde_json::{Value, json};

fn candidate_files() -> Vec<CandidateFile<'static>> {
    vec![
        CandidateFile {
            path: "dist/index.html",
            media_type: "text/html",
            bytes: b"<h1>Libre AI</h1>\n",
        },
        CandidateFile {
            path: "dist/app.css",
            media_type: "text/css",
            bytes: b"body{color:#111}\n",
        },
    ]
}

fn file_entries(files: &[CandidateFile<'_>]) -> Vec<Value> {
    files
        .iter()
        .rev()
        .map(|file| {
            json!({
                "path": file.path,
                "size": file.bytes.len(),
                "digest": sha256_hex(file.bytes),
                "mediaType": file.media_type,
            })
        })
        .collect()
}

fn passing_evidence(subject: &str, subject_digest: &str) -> Value {
    json!({
        "schemaVersion": "libre-ai.evidence-report.v1",
        "id": "urn:libre-ai:evidence:artifact-candidate-1",
        "subject": subject,
        "subjectDigest": subject_digest,
        "status": "pass",
        "checks": [{
            "id": "artifact-integrity",
            "status": "pass",
            "ruleVersion": "1.0.0"
        }],
        "generatedAt": "2026-07-17T00:00:00Z",
        "producer": {
            "name": "artifact-qualification",
            "version": "1.0.0"
        }
    })
}

fn manifest_with_evidence(
    artifact_type: &str,
    files: &[CandidateFile<'_>],
    evidence: &Value,
) -> Value {
    let id = "urn:libre-ai:artifact:candidate-1";
    let digest = artifact_content_digest(files).expect("candidate digest");
    let evidence_digest = canonical_document_digest(evidence).expect("evidence digest");
    json!({
        "schemaVersion": "libre-ai.artifact-manifest.v1",
        "id": id,
        "artifactType": artifact_type,
        "createdAt": "2026-07-17T00:00:01Z",
        "digest": digest,
        "files": file_entries(files),
        "evidenceReport": {
            "id": evidence["id"],
            "digest": evidence_digest,
            "mediaType": "application/json"
        }
    })
}

fn valid_release() -> (Vec<CandidateFile<'static>>, Value, Value) {
    let files = candidate_files();
    let digest = artifact_content_digest(&files).expect("candidate digest");
    let evidence = passing_evidence("urn:libre-ai:artifact:candidate-1", &digest);
    let manifest = manifest_with_evidence("release", &files, &evidence);
    (files, manifest, evidence)
}

fn verifier() -> ArtifactVerifier {
    ArtifactVerifier::embedded().expect("embedded contracts compile")
}

#[test]
fn passing_evidence_unlocks_a_content_addressed_release_candidate() {
    let (files, manifest, evidence) = valid_release();

    let verified = verifier()
        .verify_candidate(&manifest, Some(&evidence), &files)
        .expect("candidate is verified");

    assert_eq!(verified.kind, ArtifactKind::Release);
    assert_eq!(verified.id, "urn:libre-ai:artifact:candidate-1");
    assert_eq!(verified.digest, artifact_content_digest(&files).unwrap());
    assert_eq!(verified.file_count, 2);
    assert_eq!(
        verified.evidence.expect("bound evidence").id,
        "urn:libre-ai:evidence:artifact-candidate-1"
    );
}

#[test]
fn passing_evidence_also_unlocks_a_build_candidate() {
    let (files, mut manifest, evidence) = valid_release();
    manifest["artifactType"] = json!("build");

    let verified = verifier()
        .verify_candidate(&manifest, Some(&evidence), &files)
        .expect("build candidate is verified");
    assert_eq!(verified.kind, ArtifactKind::Build);
}

#[test]
fn content_digest_is_independent_from_input_and_manifest_order() {
    let files = candidate_files();
    let reversed = files.iter().copied().rev().collect::<Vec<_>>();

    assert_eq!(
        artifact_content_digest(&files).unwrap(),
        artifact_content_digest(&reversed).unwrap()
    );
    assert_eq!(
        artifact_content_digest(&files).unwrap(),
        "2ab7d622416286a206a052aa428eb8e743bfa4acb0db16f66fbb103a813f78e1"
    );

    let digest = artifact_content_digest(&files).unwrap();
    let evidence = passing_evidence("urn:libre-ai:artifact:candidate-1", &digest);
    let mut manifest = manifest_with_evidence("release", &files, &evidence);
    manifest["files"].as_array_mut().unwrap().reverse();
    verifier()
        .verify_candidate(&manifest, Some(&evidence), &reversed)
        .expect("order has no authority");
}

#[test]
fn manifest_path_traversal_fails_at_the_contract_boundary() {
    let (files, mut manifest, evidence) = valid_release();
    manifest["files"][0]["path"] = json!("../secret");

    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::ManifestSchemaInvalid)
    );
}

#[test]
fn hostile_and_non_portable_candidate_paths_are_refused_before_digesting() {
    for path in [
        "../secret",
        "dist/../secret",
        "/absolute",
        "C:/absolute",
        "C:drive-relative",
        "dist\\file",
        "dist//file",
        "./file",
        "dist/./file",
        "dist/trailing/",
        "dist/control\nname",
        "dist/résultat.json",
    ] {
        let files = [CandidateFile {
            path,
            media_type: "text/plain",
            bytes: b"secret",
        }];

        assert_eq!(
            artifact_content_digest(&files),
            Err(ArtifactRefusal::CandidatePathInvalid),
            "{}",
            path.escape_default()
        );
    }
}

#[test]
fn duplicate_paths_are_refused_even_when_the_schema_accepts_the_array() {
    let (files, mut manifest, evidence) = valid_release();
    manifest["files"][1] = manifest["files"][0].clone();

    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::DuplicatePath)
    );
}

#[test]
fn missing_extra_and_duplicate_candidate_files_are_refused() {
    let (files, manifest, evidence) = valid_release();
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files[..1]),
        Err(ArtifactRefusal::FileSetMismatch)
    );

    let mut extra = files.clone();
    extra.push(CandidateFile {
        path: "dist/extra.txt",
        media_type: "text/plain",
        bytes: b"extra",
    });
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &extra),
        Err(ArtifactRefusal::FileSetMismatch)
    );

    let duplicate = [files[0], files[0]];
    assert_eq!(
        artifact_content_digest(&duplicate),
        Err(ArtifactRefusal::DuplicatePath)
    );
}

#[test]
fn invalid_candidate_media_type_is_refused() {
    let files = [CandidateFile {
        path: "dist/index.html",
        media_type: "Text/HTML",
        bytes: b"content",
    }];

    assert_eq!(
        artifact_content_digest(&files),
        Err(ArtifactRefusal::CandidateMediaTypeInvalid)
    );
}

#[test]
fn altered_bytes_are_refused_without_echoing_content() {
    let (_, manifest, evidence) = valid_release();
    let files = [
        CandidateFile {
            path: "dist/index.html",
            media_type: "text/html",
            bytes: b"<h1>Hostile!</h1>\n",
        },
        CandidateFile {
            path: "dist/app.css",
            media_type: "text/css",
            bytes: b"body{color:#111}\n",
        },
    ];

    let refusal = verifier()
        .verify_candidate(&manifest, Some(&evidence), &files)
        .expect_err("digest mismatch is refused");
    assert_eq!(refusal, ArtifactRefusal::FileDigestMismatch);
    assert_eq!(refusal.code(), "artifact.file-digest-mismatch");
}

#[test]
fn size_and_media_type_mismatches_are_distinct_refusals() {
    let (files, mut manifest, evidence) = valid_release();
    manifest["files"][0]["size"] = json!(999);
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::FileSizeMismatch)
    );

    let (_, mut manifest, _) = valid_release();
    manifest["files"][0]["mediaType"] = json!("text/plain");
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::FileMediaTypeMismatch)
    );
}

#[test]
fn aggregate_manifest_digest_mismatch_is_refused() {
    let (files, mut manifest, evidence) = valid_release();
    manifest["digest"] = json!("d".repeat(64));

    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::ManifestDigestMismatch)
    );
}

#[test]
fn build_and_release_manifests_cannot_omit_the_evidence_reference() {
    for artifact_type in ["build", "release"] {
        let (files, mut manifest, evidence) = valid_release();
        manifest["artifactType"] = json!(artifact_type);
        manifest.as_object_mut().unwrap().remove("evidenceReport");

        assert_eq!(
            verifier().verify_candidate(&manifest, Some(&evidence), &files),
            Err(ArtifactRefusal::ManifestSchemaInvalid),
            "{artifact_type}"
        );
    }
}

#[test]
fn release_requires_the_exact_referenced_evidence_document() {
    let (files, manifest, _) = valid_release();
    assert_eq!(
        verifier().verify_candidate(&manifest, None, &files),
        Err(ArtifactRefusal::EvidenceRequired)
    );

    let (_, manifest, mut evidence) = valid_release();
    evidence["producer"]["version"] = json!("1.0.1");
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::EvidenceReferenceMismatch)
    );
}

#[test]
fn evidence_reference_media_type_is_part_of_the_binding() {
    let (files, mut manifest, evidence) = valid_release();
    manifest["evidenceReport"]["mediaType"] = json!("application/octet-stream");

    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::EvidenceReferenceMismatch)
    );
}

#[test]
fn failed_or_inconsistent_evidence_cannot_unlock_a_release() {
    let (files, _, mut evidence) = valid_release();
    evidence["status"] = json!("fail");
    evidence["checks"][0]["status"] = json!("fail");
    evidence["checks"][0]["reasonCode"] = json!("integrity.failed");
    let manifest = manifest_with_evidence("release", &files, &evidence);
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::EvidenceNotPassing)
    );

    let (_, manifest, mut evidence) = valid_release();
    evidence["checks"][0]["status"] = json!("fail");
    evidence["checks"][0]["reasonCode"] = json!("integrity.failed");
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::EvidenceSchemaInvalid)
    );
}

#[test]
fn evidence_subject_must_bind_the_manifest_id_and_content_digest() {
    let (files, _, mut evidence) = valid_release();
    evidence["subject"] = json!("urn:libre-ai:artifact:other");
    let manifest = manifest_with_evidence("release", &files, &evidence);
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::EvidenceSubjectMismatch)
    );

    let (_, _, mut evidence) = valid_release();
    evidence["subjectDigest"] = json!("e".repeat(64));
    let manifest = manifest_with_evidence("release", &files, &evidence);
    assert_eq!(
        verifier().verify_candidate(&manifest, Some(&evidence), &files),
        Err(ArtifactRefusal::EvidenceSubjectMismatch)
    );
}

#[test]
fn non_release_artifact_may_be_verified_without_evidence() {
    let files = candidate_files();
    let manifest = json!({
        "schemaVersion": "libre-ai.artifact-manifest.v1",
        "id": "urn:libre-ai:artifact:dataset-1",
        "artifactType": "dataset",
        "createdAt": "2026-07-17T00:00:01Z",
        "digest": artifact_content_digest(&files).unwrap(),
        "files": file_entries(&files)
    });

    let verified = verifier()
        .verify_candidate(&manifest, None, &files)
        .expect("dataset candidate is verified");
    assert_eq!(verified.kind, ArtifactKind::Dataset);
    assert!(verified.evidence.is_none());
}
