//! Read-only admission checks for a recovery candidate. The supervisor never
//! instantiates this module. No host import is admitted until the recovery ABI
//! and its generation-scoped authority have passed fault qualification.
use sha2::{Digest, Sha256};
use std::error::Error;
use std::io::Read;
use std::path::Path;
use wasmparser::{ExternalKind, FunctionBody, Operator, Parser, Payload, Validator, WasmFeatures};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub const MAX_BYTES: usize = 65536;
const MAX_PAGES: u64 = 16;
const MAX_FUNCTIONS: u32 = 128;
const MAX_LOCALS: u32 = 256;
const MAX_INSTRUCTIONS: u32 = 8192;
const MAX_DEPTH: u32 = 64;

#[derive(Debug)]
pub struct Inspection {
    pub sha256: String,
    pub entry: &'static str,
    pub function: u32,
    pub initial_pages: u64,
    pub maximum_pages: u64,
    pub instructions: u32,
}

fn count_body(body: FunctionBody<'_>, total: &mut u32) -> Result<()> {
    let mut locals = 0;
    for group in body.get_locals_reader()? {
        let (count, _) = group?;
        if count > MAX_LOCALS - locals {
            return Err("recovery function exceeds the local budget".into());
        }
        locals += count;
    }
    let mut ops = body.get_operators_reader()?;
    let mut depth: u32 = 1;
    while !ops.eof() {
        *total += 1;
        if *total > MAX_INSTRUCTIONS {
            return Err("recovery module exceeds the instruction budget".into());
        }
        match ops.read()? {
            Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err("recovery function exceeds the control depth budget".into());
                }
            }
            Operator::End => depth = depth.checked_sub(1).ok_or("unbalanced function end")?,
            _ => {}
        }
    }
    Ok(())
}

/// Validate the exact bytes that are hashed. Budgets are checked before the
/// full MVP type and instruction validator. A successful result has zero
/// imports, one bounded private memory and exactly one unambiguous entry.
pub fn inspect(bytes: &[u8]) -> Result<Inspection> {
    if bytes.len() > MAX_BYTES || !bytes.starts_with(b"\0asm\x01\0\0\0") {
        return Err("expected a bounded core Wasm module".into());
    }
    let mut parser = Parser::new(0);
    parser.set_features(WasmFeatures::MVP);
    let mut entry = None;
    let mut memory = None;
    let mut count = 0;
    for item in parser.parse_all(bytes) {
        match item? {
            Payload::Version { .. } | Payload::End(_) => {}
            Payload::CustomSection(s) => {
                if s.name().starts_with("component-type") || s.name() == "component-name" {
                    return Err("component metadata is outside the recovery profile".into());
                }
            }
            Payload::TypeSection(s) if s.count() <= MAX_FUNCTIONS => {
                for ty in s.into_iter_err_on_gc_types() {
                    if ty?.params().len() > 32 {
                        return Err("recovery function exceeds the parameter budget".into());
                    }
                }
            }
            Payload::ImportSection(s) if s.count() == 0 => {}
            Payload::FunctionSection(s) if s.count() <= MAX_FUNCTIONS => {}
            Payload::TableSection(s) if s.count() <= 1 => {
                for item in s {
                    let ty = item?.ty;
                    if ty.maximum.is_none_or(|max| max > 256 || ty.initial > max) {
                        return Err("recovery table needs a maximum of at most 256 elements".into());
                    }
                }
            }
            Payload::MemorySection(s) if s.count() == 1 && memory.is_none() => {
                let ty = s.into_iter().next().ok_or("missing memory")??;
                let max = ty.maximum.ok_or("missing recovery memory maximum")?;
                if ty.memory64
                    || ty.shared
                    || ty.page_size_log2.is_some()
                    || max > MAX_PAGES
                    || ty.initial > max
                {
                    return Err("expected one bounded private wasm32 memory".into());
                }
                memory = Some((ty.initial, max));
            }
            Payload::GlobalSection(s) if s.count() <= 64 => {}
            Payload::ExportSection(s) if s.count() <= 1 => {
                for item in s {
                    let export = item?;
                    if export.name != "_start"
                        || export.kind != ExternalKind::Func
                        || entry.is_some()
                    {
                        return Err("expected only one _start function or start section".into());
                    }
                    entry = Some(("_start", export.index));
                }
            }
            Payload::StartSection { func, .. } if entry.is_none() => {
                entry = Some(("start-section", func))
            }
            Payload::ElementSection(s) if s.count() <= 128 => {}
            Payload::DataSection(s) if s.count() <= 128 => {}
            Payload::CodeSectionStart { count, .. } if count <= MAX_FUNCTIONS => {}
            Payload::CodeSectionEntry(body) => count_body(body, &mut count)?,
            _ => {
                return Err("unexpected recovery module section or section budget exceeded".into())
            }
        }
    }
    let (entry, function) = entry.ok_or("missing recovery entry")?;
    let (initial_pages, maximum_pages) = memory.ok_or("missing recovery memory")?;
    // An ordinary Wasm function export can have any signature. After validation,
    // its index refers to a real function, including when selected by start.
    let validated = Validator::new_with_features(WasmFeatures::MVP).validate_all(bytes)?;
    let ty = &validated[validated.as_ref().core_function_at(function)].unwrap_func();
    if !ty.params().is_empty() || !ty.results().is_empty() {
        return Err("recovery entry must have signature () -> ()".into());
    }
    Ok(Inspection {
        sha256: format!("{:x}", Sha256::digest(bytes)),
        entry,
        function,
        initial_pages,
        maximum_pages,
        instructions: count,
    })
}

/// Inspect a bounded snapshot from one regular file descriptor. Opening a FIFO
/// cannot block the operator, and a final symlink is refused.
pub fn inspect_file(path: &Path) -> Result<Inspection> {
    let file = crate::manifest::open_regular(path, MAX_BYTES as u64)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    inspect(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // One bounded memory and one defined () -> () function. Tests choose its
    // entry and code sections independently so invalid modules reach validation.
    fn candidate(entry: &[u8], code: &[u8]) -> Vec<u8> {
        [
            b"\0asm\x01\0\0\0\x01\x04\x01\x60\0\0\x03\x02\x01\0\x05\x04\x01\x01\x01\x02",
            entry,
            code,
        ]
        .concat()
    }

    const EXPORT: &[u8] = b"\x07\x0a\x01\x06_start\0\0";
    const START: &[u8] = b"\x08\x01\0";
    const NOOP: &[u8] = b"\x0a\x05\x01\x03\0\x01\x0b";

    #[test]
    fn entry_is_unique_and_identifies_the_validated_bytes() {
        for (entry, name) in [(EXPORT, "_start"), (START, "start-section")] {
            let bytes = candidate(entry, NOOP);
            let r = inspect(&bytes).unwrap();
            assert_eq!(r.entry, name);
            assert_eq!(
                (r.function, r.initial_pages, r.maximum_pages, r.instructions),
                (0, 1, 2, 2)
            );
            assert_eq!(r.sha256, format!("{:x}", Sha256::digest(&bytes)));
        }
        assert!(inspect(&candidate(&[EXPORT, START].concat(), NOOP)).is_err());
        assert!(inspect(&candidate(&[], NOOP)).is_err());
    }

    #[test]
    fn all_code_is_checked_for_types_and_extensions() {
        // i32.const 1; i32.extend8_s; drop. Valid once sign extension is enabled.
        assert!(inspect(&candidate(
            EXPORT,
            b"\x0a\x08\x01\x06\0\x41\x01\xc0\x1a\x0b"
        ))
        .is_err());
        // i64.const 1; i32.eqz; drop. Invalid operand type in any core profile.
        assert!(inspect(&candidate(
            EXPORT,
            b"\x0a\x08\x01\x06\0\x42\x01\x45\x1a\x0b"
        ))
        .is_err());
    }
}
