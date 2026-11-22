//! Resolution of local deployment and per-VM recommendation documents.
use super::{attr, attributes, document, id, local_file, path, xml_contents, Result, MAX_XML};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};

const MAX_DOCUMENTS: usize = 256;
const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Kind {
    Deployment,
    Recommendations,
}

/// A snapshot of every XML input consumed in one review. Repeated includes read
/// the same bytes even if the filesystem changes while the operator reviews.
pub struct Bundle<'a> {
    directory: &'a File,
    documents: BTreeMap<PathBuf, String>,
    bytes: usize,
}

pub struct Expanded {
    pub xml: String,
    pub digest: String,
    pub inputs: Vec<PathBuf>,
}

impl<'a> Bundle<'a> {
    pub fn new(directory: &'a File) -> Self {
        Self { directory, documents: BTreeMap::new(), bytes: 0 }
    }

    fn load(&mut self, name: &Path) -> Result<&str> {
        if !self.documents.contains_key(name) {
            if self.documents.len() >= MAX_DOCUMENTS {
                return Err("deployment XML document count exceeds budget".into());
            }
            let xml = xml_contents(local_file(self.directory, name)?)
                .map_err(|error| format!("invalid XML input {name:?}: {error}"))?;
            if xml.len() > MAX_TOTAL_BYTES - self.bytes {
                return Err("deployment XML inputs exceed total byte budget".into());
            }
            self.bytes += xml.len();
            self.documents.insert(name.to_owned(), xml);
        }
        Ok(&self.documents[name])
    }

    /// All includes resolve relative to the pinned bundle root. A diamond
    /// contributes its common declaration once within each individual graph.
    pub fn expand(&mut self, name: &Path, kind: Kind) -> Result<Expanded> {
        let mut state = Walk {
            active: BTreeSet::new(), inputs: BTreeSet::new(), flat: String::new(),
        };
        self.visit(name, kind, &mut state)?;
        let digest = if state.inputs.len() == 1 {
            format!("{:x}", Sha256::digest(self.documents[name].as_bytes()))
        } else {
            let mut hash = Sha256::new();
            hash.update(b"wros local XML dependency graph v1\0");
            for input in &state.inputs {
                let filename = input.as_os_str().as_encoded_bytes();
                let content = self.documents[input].as_bytes();
                for field in [filename, content] {
                    hash.update((field.len() as u64).to_le_bytes());
                    hash.update(field);
                }
            }
            format!("{:x}", hash.finalize())
        };
        Ok(Expanded { xml: state.flat, digest, inputs: state.inputs.into_iter().collect() })
    }

    fn visit(&mut self, name: &Path, kind: Kind, state: &mut Walk) -> Result<()> {
        if state.active.contains(name) {
            return Err(format!("cyclic XML dependency at {name:?}"));
        }
        if state.inputs.contains(name) {
            return Ok(());
        }
        if state.active.len() >= MAX_DEPTH {
            return Err("XML dependency depth exceeds budget".into());
        }
        let outer = state.active.is_empty();
        state.active.insert(name.to_owned());
        state.inputs.insert(name.to_owned());
        // Finish parsing this pinned document before descending. Nodes borrow
        // its original bytes, so only bounded, checked child spans are queued.
        let raw = self.load(name)?;
        let doc = document(raw)?;
        let root = doc.root_element();
        let expected = match (kind, outer) {
            (Kind::Recommendations, _) => "recommendations",
            (Kind::Deployment, true) => "deployment",
            (Kind::Deployment, false) => "deployment-fragment",
        };
        if outer && kind == Kind::Deployment {
            attributes(root, expected, &["id"])?;
            let deployment = attr(root, "id")?;
            if !id(deployment) {
                return Err("invalid deployment ID".into());
            }
            state.append(&format!("<deployment id=\"{deployment}\">"))?;
        } else {
            attributes(root, expected, &[])?;
            if outer { state.append("<recommendations>")?; }
        }
        let mut children = Vec::new();
        for node in root.children().filter(roxmltree::Node::is_element) {
            match node.tag_name().name() {
                "include" => {
                    attributes(node, "include", &["file"])?;
                    if node.children().any(|child| child.is_element()) {
                        return Err("an XML include must be a leaf".into());
                    }
                    children.push(Child::Include(path(attr(node, "file")?)?));
                }
                "supervisor" if !outer && kind == Kind::Deployment =>
                    return Err("only the root deployment may declare a supervisor".into()),
                _ => children.push(Child::Declaration(node.range())),
            }
        }
        for child in children {
            match child {
                Child::Include(input) => self.visit(&input, kind, state)?,
                Child::Declaration(range) => state.append(&self.documents[name][range])?,
            }
        }
        if outer {
            state.append(if kind == Kind::Deployment { "</deployment>" } else { "</recommendations>" })?;
        }
        state.active.remove(name);
        Ok(())
    }

    /// Re-open each path beneath the same directory before consuming approval.
    pub fn revalidate(&self) -> Result<()> {
        for (name, reviewed) in &self.documents {
            if xml_contents(local_file(self.directory, name)?)? != *reviewed {
                return Err(format!("reviewed XML input {name:?} changed before activation"));
            }
        }
        Ok(())
    }
}

enum Child { Include(PathBuf), Declaration(std::ops::Range<usize>) }

struct Walk {
    active: BTreeSet<PathBuf>,
    inputs: BTreeSet<PathBuf>,
    flat: String,
}
impl Walk {
    fn append(&mut self, text: &str) -> Result<()> {
        if text.len() > MAX_XML as usize - self.flat.len() {
            return Err("expanded XML exceeds byte budget".into());
        }
        self.flat.push_str(text);
        Ok(())
    }
}
