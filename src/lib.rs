pub mod attachment;
pub mod audit;
pub mod cgroup;
pub mod containment;
pub mod devices;
pub mod manifest;
pub mod ownership;
pub mod placement;
pub mod recovery;
#[cfg(feature = "recovery-preflight")]
pub mod recovery_module;
pub mod service;
pub mod state;
pub mod supervisor;
pub mod verdict;
pub mod verification;

// A fork duplicates the other libtest threads' live flock descriptors until
// its child exits. Keep tests that fork or verify final-close semantics apart.
#[cfg(test)]
pub(crate) static FORK_AND_LOCK_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());
