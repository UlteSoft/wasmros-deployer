//! Local, bounded, closed XML deployment and recommendation formats.
use roxmltree::{Document, Node, ParsingOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_XML: u64 = 256 * 1024;
#[derive(Debug)]
pub struct Process {
    pub id: String, pub module: PathBuf, pub digest: String, pub policy: PathBuf,
    pub boot_start: bool, pub crash_restart: bool, pub recommendations: Option<PathBuf>, pub memory_bytes: u64, pub pids: u32,
}
#[derive(Debug)]
pub struct DriverArtifact {
    pub id:String, pub file:PathBuf, pub digest:String, pub vendor_version:String, pub kind:String,
    pub hardware_id:String,
}
#[derive(Debug)]
pub struct Deployment {pub id: String, pub processes: Vec<Process>,pub drivers:Vec<DriverArtifact>}
pub fn read_xml(p: &Path) -> Result<String> {
    let f = File::open(p).map_err(|e| e.to_string())?;
    if !f.metadata().map_err(|e|e.to_string())?.is_file() { return Err("expected regular XML file".into()); }
    let mut data=String::new();f.take(MAX_XML+1).read_to_string(&mut data).map_err(|e|e.to_string())?;
    if data.len() as u64>MAX_XML{return Err("XML exceeds byte budget".into())} Ok(data)
}
fn document(s:&str)->Result<Document<'_>> {
    if s.len() as u64 > MAX_XML {return Err("XML exceeds byte budget".into())}
    let mut options=ParsingOptions::default(); options.allow_dtd=false;options.nodes_limit=4096;
    Document::parse_with_options(s,options).map_err(|e|e.to_string())
}
fn attributes(n:Node,name:&str,allowed:&[&str])->Result<()> {
    if n.tag_name().name()!=name || n.tag_name().namespace().is_some()
        || n.namespaces().next().is_some() || n.attributes().any(|a|a.namespace().is_some()||!allowed.contains(&a.name()))
        || n.children().any(|x|x.is_pi() || (x.is_text() && !x.text().unwrap_or("").trim().is_empty())) {
        return Err(format!("unexpected element, attribute or content in {name}"))
    } Ok(())
}
fn attr<'a>(n:Node<'a,'a>,key:&str)->Result<&'a str>{n.attribute(key).filter(|s|!s.is_empty()).ok_or_else(||format!("missing {key}"))}
fn flag(node:Node,name:&str)->Result<bool>{
    match node.attribute(name){None|Some("false")=>Ok(false),Some("true")=>Ok(true),_=>Err(format!("invalid boolean {name}"))}
}
pub fn known_interface(key:&str)->bool{include_str!("../protocol/ros-interfaces.txt").lines().any(|name|name==key)}
fn id(s:&str)->bool{s.len()<=128 && !s.is_empty() && s.bytes().all(|b|b.is_ascii_alphanumeric() || b"_-".contains(&b))}
fn path(s:&str)->Result<PathBuf> {
    let p=Path::new(s);
    if s.contains(':')||s.contains('\\'){return Err("expected a local path without a URI scheme".into())}
    if s.is_empty() || s.bytes().any(|x|x<32||x==127) || !p.components().all(|c|matches!(c,Component::Normal(_))) {return Err("expected bundle-relative path".into())} Ok(p.into())
}
pub fn deployment(s:&str)->Result<Deployment>{
    let d=document(s)?;let root=d.root_element();attributes(root,"deployment",&["id"])?;
    let name=attr(root,"id")?;if !id(name){return Err("invalid deployment ID".into())}
    let mut processes=Vec::new();let mut drivers=Vec::new();let mut hardware=BTreeSet::new();let mut ids=BTreeSet::new();
    for node in root.children().filter(Node::is_element){
        if node.tag_name().name()=="driver"{
            attributes(node,"driver",&["id","file","sha256","vendor-version","kind","hardware-id"])?;
            let name=attr(node,"id")?;let key=attr(node,"hardware-id")?;let digest=attr(node,"sha256")?;
            let kind=attr(node,"kind")?;let version=attr(node,"vendor-version")?;
            if drivers.len()>=128 || !id(name)||!id(key)||!ids.insert(name)||!hardware.insert(key)
                ||!matches!(kind,"shared-library"|"executable")||digest.len()!=64
                ||!digest.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
                || version.len()>128 || !version.bytes().all(|b|b.is_ascii_graphic())||node.children().any(|n|n.is_element()){
                return Err("invalid driver or conflicting hardware owner".into())
            }
            drivers.push(DriverArtifact{id:name.into(),file:path(attr(node,"file")?)?,digest:digest.into(),
                hardware_id:key.into(),kind:kind.into(),vendor_version:version.into()});
            continue
        }
        attributes(node,"vm",&["id","module","sha256","policy","recommendations","memory-bytes","pids","start-on-boot","restart-on-crash"])?;
        let name=attr(node,"id")?;let digest=attr(node,"sha256")?;
        if node.children().any(|n|n.is_element())||processes.len()>=128||!id(name)||!ids.insert(name)||
            digest.len()!=64||!digest.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err("invalid or duplicate VM identity or digest".into())}
        let memory_bytes=attr(node,"memory-bytes")?.parse::<u64>().map_err(|_|"invalid memory budget")?;
        let pids=attr(node,"pids")?.parse::<u32>().map_err(|_|"invalid task budget")?;
        if memory_bytes==0||pids==0{return Err("process budgets must be positive".into())}
        processes.push(Process{id:name.into(),module:path(attr(node,"module")?)?,digest:digest.into(),
            policy:path(attr(node,"policy")?)?,boot_start:flag(node,"start-on-boot")?,crash_restart:flag(node,"restart-on-crash")?,recommendations:node.attribute("recommendations").map(path).transpose()?,memory_bytes,pids})
    }
    if processes.is_empty(){return Err("empty deployment".into())} Ok(Deployment{id:name.into(),processes,drivers})
}
pub fn recommendations(s:&str)->Result<BTreeMap<String,bool>>{
    let d=document(s)?;let root=d.root_element();attributes(root,"recommendations",&[])?;
    let mut grants=BTreeMap::new();
    for n in root.children().filter(Node::is_element){
        attributes(n,"interface",&["name","expose"])?;
        let key=attr(n,"name")?;
        if !known_interface(key)||grants.len()>=512||key.len()>128||!key.split('.').all(|x|id(x))||n.children().any(|n|n.is_element()){return Err("invalid interface".into())}
        let enabled=match attr(n,"expose")?{"allow"=>true,"deny"=>false,_=>return Err("invalid exposure".into())};
        if grants.insert(key.into(),enabled).is_some(){return Err("duplicate interface".into())}
    }Ok(grants)
}
pub fn local_file(root:&Path, relative:&Path)->Result<PathBuf>{
    let p=root.join(relative).canonicalize().map_err(|e|e.to_string())?;
    if !p.starts_with(root)||!p.is_file(){return Err("file outside bundle or missing".into())} Ok(p)
}
pub fn sha256(path:&Path)->Result<String>{
    use sha2::{Digest,Sha256};
    let mut f=File::open(path).map_err(|e|e.to_string())?;let mut hash=Sha256::new();
    io::copy(&mut f,&mut hash).map_err(|e|e.to_string())?;Ok(format!("{:x}",hash.finalize()))
}
