//! Session-creation benchmark only; no guest import or production command.
use std::time::Instant;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 2);
    let count: u64 = args[1].parse().unwrap();
    assert!((1..=100000).contains(&count));
    for _ in 0..100 { std::hint::black_box(wros_deployer::attachment::endpoints().unwrap()); }
    let start=Instant::now();
    for _ in 0..count { std::hint::black_box(wros_deployer::attachment::endpoints().unwrap()); }
    println!("{{\"pairs\":{count},\"ns_per_pair\":{},\"pid\":{}}}", start.elapsed().as_nanos() as f64/count as f64,std::process::id());
}
