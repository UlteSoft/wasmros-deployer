//! Bounded inventory of static imports from the exact admitted Wasm bytes.

use crate::manifest::Result;
use std::fs::File;

#[derive(Debug, Eq, PartialEq)]
pub enum ImportAssessment {
    /// A complete list of declared imports. Resolution is a separate VM operation.
    Complete { imports: Vec<(String, String)> },
    Unassessed { reason: &'static str },
}

/// Workload declarations in runtime-owned namespaces must use the public guest
/// ABI. A business library can independently export fields named "debug" or
/// "control". Only the namespace owner determines whether a field is a host API.
pub fn check_host_import(namespace: &str, field: &str) -> Result<()> {
    let refused = match namespace {
        "uwvm_ros_v2" => !crate::manifest::known_interface(field),
        "uwvm_ros1_v1" | "uwvm_ros2_v1" => field != "abi_version",
        "wasi_snapshot_preview1" | "wasi_unstable" => field.starts_with("sock_"),
        "wros_deployer" | "wros.deployer" => true,
        name => name.starts_with("uwvm_") || name.starts_with("uwvm:")
            || name.starts_with("wros:") || name.starts_with("wasi:sockets/"),
    };
    if refused {
        return Err(format!("STARTUP BLOCKED: forbidden workload host import {namespace:?}.{field:?}; managed IPC requires a provisioned business attachment"));
    }
    Ok(())
}

pub fn require_complete(assessment: ImportAssessment) -> Result<ImportAssessment> {
    match assessment {
        ImportAssessment::Unassessed { reason } => Err(format!("workload admission requires a complete import inventory: {reason}")),
        complete => Ok(complete),
    }
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
    use wasmparser::{BinaryReader, ImportSectionReader, TypeRef};

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
    let mut type_section = None;
    let mut host_types = std::collections::BTreeMap::<u32, Vec<(&[wasmparser::ValType], usize)>>::new();
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
        if header[0] == 1 {
            if type_section.replace((start, length)).is_some() {
                return unassessed("duplicate Wasm type section");
            }
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
            check_host_import(entry.module, entry.name)?;
            name_bytes += entry.module.len() + entry.name.len();
            if imports.len() == MAX_IMPORTS || name_bytes > MAX_NAME_BYTES {
                return unassessed("Wasm import inventory exceeds the display budget");
            }
            if let Some(parameters) = host_parameters(entry.module, entry.name) {
                let index = match entry.ty {
                    TypeRef::Func(index) | TypeRef::FuncExact(index) => index,
                    _ => return Err(format!("STARTUP BLOCKED: host import {:?}.{:?} requires a function", entry.module, entry.name)),
                };
                host_types.entry(index).or_default().push((parameters, imports.len()));
            }
            imports.push((entry.module.to_owned(), entry.name.to_owned()));
        }
        import_section = Some(imports);
    }
    let imports = import_section.unwrap_or_default();
    if !host_types.is_empty() {
        let (start, length) = type_section.ok_or("STARTUP BLOCKED: host function import has no type section")?;
        if length > crate::manifest::libraries::MAX_IMAGE_BYTES {
            return unassessed("Wasm type section exceeds the admitted image budget");
        }
        let mut section = vec![0; length as usize];
        read(start, &mut section).map_err(|error| error.to_string())?;
        let types = wasmparser::TypeSectionReader::new(BinaryReader::new(&section, start))
            .map_err(|e| format!("invalid Wasm type section: {e}"))?;
        // Type indices include all members of recursive groups. Inspect only the
        // requested function types. Guest instructions and custom extensions stay opaque.
        let mut index = 0;
        for group in types {
            for ty in group.map_err(|e| format!("invalid Wasm type group: {e}"))?.into_types() {
                if let Some(expected) = host_types.remove(&index) {
                    for (parameters, position) in expected {
                        if !matches!(&ty.composite_type.inner, wasmparser::CompositeInnerType::Func(f)
                            if f.params() == parameters && f.results() == [wasmparser::ValType::I32]) {
                            let (ns, field) = &imports[position];
                            return Err(format!("STARTUP BLOCKED: incompatible host function signature for {ns:?}.{field:?}; expected {parameters:?} -> [I32]"));
                        }
                    }
                }
                index += 1;
            }
            if host_types.is_empty() { break; }
        }
        if let Some((index, uses)) = host_types.first_key_value() {
            let (ns, field) = &imports[uses[0].1];
            return Err(format!("STARTUP BLOCKED: host import {ns:?}.{field:?} references missing function type {index}"));
        }
    }
    Ok(ImportAssessment::Complete { imports })
}

/// Exact published product signatures. The clock selector remains i32 for
/// both address widths. Every managed ROSv2 host function returns one i32.
#[cfg(feature = "recovery-preflight")]
fn host_parameters(namespace: &str, field: &str) -> Option<&'static [wasmparser::ValType]> {
    use wasmparser::ValType::{I32, I64};
    match (namespace, field) {
        ("uwvm_ros_v2", "abi") | ("uwvm_ros1_v1" | "uwvm_ros2_v1", "abi_version") => Some(&[]),
        ("uwvm_ros_v2", "capability.open") => Some(&[I32, I64, I64, I64]),
        ("uwvm_ros_v2", "capability.close") => Some(&[I64]),
        ("uwvm_ros_v2", name) if crate::manifest::known_interface(name) => Some(&[I64, I32, I64, I64, I64, I64, I64]),
        ("wasi_snapshot_preview1", "clock_time_get") => Some(&[I32, I64, I32]),
        ("wasi_snapshot_preview1", "clock_time_get_wasm64") => Some(&[I32, I64, I64]),
        ("wasi_snapshot_preview1", "clock_res_get") => Some(&[I32, I32]),
        ("wasi_snapshot_preview1", "clock_res_get_wasm64") => Some(&[I32, I64]),
        _ => None,
    }
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
    fn managed_host_imports_cannot_request_external_endpoints() {
        for (module, name) in [("uwvm_ros_v2", "driver.direct-connect"), ("uwvm_ros_v2", "vm.dump"),
            ("uwvm_debug", "attach"), ("uwvm:update", "commit"), ("wros_deployer", "status"),
            ("wasi_snapshot_preview1", "sock_recv"), ("wasi:sockets/tcp@0.2.0", "start-connect")] {
            assert!(check_host_import(module, name).is_err(), "{module}.{name}");
        }
        for (module, name) in [("uwvm_ros_v2", "driver.connect"), ("uwvm_ros_v2", "control.result"),
            ("telemetry", "debug"), ("update_model", "control")] {
            check_host_import(module, name).unwrap();
        }
        assert!(require_complete(ImportAssessment::Unassessed { reason: "incomplete" }).is_err());
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
    fn checks_only_the_selected_type_and_keeps_instructions_opaque() {
        let mut image = b"\0asm\x01\0\0\0".to_vec();
        // An unrelated GC recursion group precedes the imported function type.
        image.extend_from_slice(&[1, 9, 2, 0x4e, 1, 0x5f, 0, 0x60, 0, 1, 0x7f]);
        let result_type = image.len()-1;
        image.extend_from_slice(b"\x02\x13\x01\x0buwvm_ros_v2\x03abi\x00\x01");
        image.extend_from_slice(&[10, 3, 1, 0xff, 0]); // Deliberately opaque extension instructions.
        assert!(matches!(memory_scan(&image), ImportAssessment::Complete { .. }));
        image[result_type] = 0x7e;
        let refusal = scan(image.len() as u64, |i, out| {
            out.copy_from_slice(&image[i as usize..i as usize + out.len()]); Ok(())
        }).unwrap_err();
        assert!(refusal.contains("incompatible host function signature"), "{refusal}");
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
