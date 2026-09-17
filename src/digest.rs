use crate::{ArtifactRefusal, CandidateFile};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_FILES: usize = 10_000;
const MAX_FILE_SIZE: u64 = 1_099_511_627_776;
const MAX_PATH_LENGTH: usize = 1_024;
const MAX_MEDIA_TYPE_LENGTH: usize = 255;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContentDescriptor<'a> {
    pub(crate) path: &'a str,
    pub(crate) size: u64,
    pub(crate) digest: String,
    pub(crate) media_type: &'a str,
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub fn canonical_document_digest(document: &Value) -> Result<String, ArtifactRefusal> {
    let canonical =
        serde_jcs::to_vec(document).map_err(|_| ArtifactRefusal::CanonicalizationFailed)?;
    Ok(sha256_hex(&canonical))
}

pub fn artifact_content_digest(files: &[CandidateFile<'_>]) -> Result<String, ArtifactRefusal> {
    descriptor_set_digest(&content_descriptors(files)?)
}

pub(crate) fn descriptor_set_digest(
    descriptors: &[ContentDescriptor<'_>],
) -> Result<String, ArtifactRefusal> {
    let canonical =
        serde_jcs::to_vec(descriptors).map_err(|_| ArtifactRefusal::CanonicalizationFailed)?;
    Ok(sha256_hex(&canonical))
}

pub(crate) fn content_descriptors<'a>(
    files: &[CandidateFile<'a>],
) -> Result<Vec<ContentDescriptor<'a>>, ArtifactRefusal> {
    if files.is_empty() {
        return Err(ArtifactRefusal::CandidateEmpty);
    }
    if files.len() > MAX_FILES {
        return Err(ArtifactRefusal::CandidateTooLarge);
    }

    let mut paths = BTreeSet::new();
    let mut descriptors = Vec::with_capacity(files.len());
    for file in files {
        if !path_is_valid(file.path) {
            return Err(ArtifactRefusal::CandidatePathInvalid);
        }
        if !media_type_is_valid(file.media_type) {
            return Err(ArtifactRefusal::CandidateMediaTypeInvalid);
        }
        if !paths.insert(file.path) {
            return Err(ArtifactRefusal::DuplicatePath);
        }
        let size =
            u64::try_from(file.bytes.len()).map_err(|_| ArtifactRefusal::CandidateTooLarge)?;
        if size > MAX_FILE_SIZE {
            return Err(ArtifactRefusal::CandidateTooLarge);
        }
        descriptors.push(ContentDescriptor {
            path: file.path,
            size,
            digest: sha256_hex(file.bytes),
            media_type: file.media_type,
        });
    }
    descriptors.sort_by(|left, right| left.path.cmp(right.path));
    Ok(descriptors)
}

fn path_is_valid(path: &str) -> bool {
    !path.is_empty()
        && path.is_ascii()
        && path.len() <= MAX_PATH_LENGTH
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && !path.bytes().any(|byte| byte.is_ascii_control())
        && !path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
}

fn media_type_is_valid(media_type: &str) -> bool {
    let length = media_type.chars().count();
    if !(3..=MAX_MEDIA_TYPE_LENGTH).contains(&length) {
        return false;
    }
    let Some((kind, subtype)) = media_type.split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && !subtype.is_empty()
        && !subtype.contains('/')
        && kind.chars().chain(subtype.chars()).all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || "!#$&^_.+-".contains(character)
        })
}
