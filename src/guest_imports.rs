//! Bounded inventory of static imports from the exact admitted Wasm bytes.

use crate::manifest::Result;
use std::fs::File;

#[derive(Debug, Eq, PartialEq)]
pub enum ImportAssessment {
    /// A complete list of declared imports. Resolution is a separate VM operation.
    Complete { imports: Vec<(String, String)> },
    Unassessed { reason: &'static str },
}

/// Inventory a pinned guest image without disturbing its file offset.
///
/// The caller establishes identity and digest. This scan does not grant an
/// import, resolve module providers, or validate executable Wasm instructions.
#[cfg(feature = "recovery-preflight")]
pub fn inspect(image: &File) -> Result<ImportAssessment> {
    use std::os::unix::fs::FileExt;

    let size = image.metadata().map_err(|error| error.to_string())?.len();
    scan(size, |offset, buffer| image.read_exact_at(buffer, offset))
}

#[cfg(not(feature = "recovery-preflight"))]
pub fn inspect(_image: &File) -> Result<ImportAssessment> {
    Ok(ImportAssessment::Unassessed {
        reason: "this build has no Wasm import reader",
    })
}

#[cfg(feature = "recovery-preflight")]
fn scan(
    size: u64,
    read: impl Fn(u64, &mut [u8]) -> std::io::Result<()>,
) -> Result<ImportAssessment> {
    use wasmparser::{BinaryReader, ImportSectionReader};

    const MAX_SECTIONS: usize = 4096;
    const MAX_SECTION_BYTES: usize = 128 * 1024;
    const MAX_IMPORTS: usize = 2048;
    const MAX_NAME_BYTES: usize = 64 * 1024;

    let unassessed = |reason| Ok(ImportAssessment::Unassessed { reason });
    let mut header = [0; 8];
    if size < header.len() as u64 {
        return unassessed("truncated Wasm header");
    }
    read(0, &mut header).map_err(|error| error.to_string())?;
    if &header != b"\0asm\x01\0\0\0" {
        return unassessed("unsupported image encoding; expected a Wasm core module");
    }

    let mut offset = header.len() as u64;
    let mut import_section = None;
    let mut sections = 0;
    while offset < size {
        if sections == MAX_SECTIONS {
            return unassessed("Wasm section inventory exceeds the assessment budget");
        }
        sections += 1;
        let mut header = [0; 6];
        let count = (size - offset).min(header.len() as u64) as usize;
        read(offset, &mut header[..count]).map_err(|error| error.to_string())?;
        let mut reader = BinaryReader::new(&header[1..count], offset + 1);
        let length = match reader.read_var_u32() {
            Ok(length) => u64::from(length),
            Err(_) => return unassessed("malformed Wasm section length"),
        };
        let start = reader.original_position();
        if length > size - start {
            return unassessed("Wasm section extends beyond the image");
        }
        offset = start + length;
        if header[0] > 13 {
            return unassessed("unsupported Wasm core section");
        }
        if header[0] != 2 {
            continue;
        }
        if import_section.is_some() {
            return unassessed("duplicate Wasm import section");
        }
        if length > MAX_SECTION_BYTES as u64 {
            return unassessed("Wasm import metadata exceeds the assessment byte budget");
        }
        let mut payload = vec![0; length as usize];
        read(start, &mut payload).map_err(|error| error.to_string())?;
        let section = match ImportSectionReader::new(BinaryReader::new(&payload, start)) {
            Ok(section) => section,
            Err(_) => return unassessed("malformed Wasm import section"),
        };
        let mut imports = Vec::new();
        let mut name_bytes = 0;
        for entry in section.into_imports() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => return unassessed("malformed Wasm import declaration"),
            };
            name_bytes += entry.module.len() + entry.name.len();
            if imports.len() == MAX_IMPORTS || name_bytes > MAX_NAME_BYTES {
                return unassessed("Wasm import inventory exceeds the display budget");
            }
            imports.push((entry.module.to_owned(), entry.name.to_owned()));
        }
        import_section = Some(imports);
    }
    Ok(ImportAssessment::Complete {
        imports: import_section.unwrap_or_default(),
    })
}

#[cfg(all(test, feature = "recovery-preflight"))]
mod tests {
    use super::*;

    fn memory_scan(bytes: &[u8]) -> ImportAssessment {
        scan(bytes.len() as u64, |offset, buffer| {
            let begin = offset as usize;
            buffer.copy_from_slice(&bytes[begin..begin + buffer.len()]);
            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn lists_function_and_shared_memory_without_interpreting_code() {
        let mut image = b"\0asm\x01\0\0\0".to_vec();
        image.extend_from_slice(b"\x02\x19\x02\x03dep\x05entry\x00\x00\x03env\x03mem\x02\x03\x01\x02");
        image.extend_from_slice(b"\x0a\x03\x01\xff\x00"); // Opaque extension bytes.
        assert_eq!(
            memory_scan(&image),
            ImportAssessment::Complete {
                imports: vec![("dep".into(), "entry".into()), ("env".into(), "mem".into())],
            }
        );
    }

    #[test]
    fn distinguishes_empty_valid_inventory_from_unknown_input() {
        assert_eq!(
            memory_scan(b"\0asm\x01\0\0\0"),
            ImportAssessment::Complete { imports: vec![] },
        );
        for bytes in [
            b"\0asm\x0d\0\x01\0".as_slice(),
            b"\0asm\x01\0\0\0\x02\x80",
            b"\0asm\x01\0\0\0\x02\x09\x00",
            b"\0asm\x01\0\0\0\x02\x01\x01",
            b"\0asm\x01\0\0\0\x02\x01\x00\x02\x01\x00",
        ] {
            assert!(matches!(memory_scan(bytes), ImportAssessment::Unassessed { .. }));
        }
    }
}
