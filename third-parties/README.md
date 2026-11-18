# Vendored Rust dependencies

`cargo/` contains the actual registry source archives unpacked by `cargo vendor`,
including their upstream license files. Exact versions and archive checksums are
pinned in the repository's `Cargo.lock`; per-file integrity is recorded in each
`.cargo-checksum.json`. `.cargo/config.toml` selects this directory for offline
builds. Do not remove upstream source files that participate in those checksums.

Local attachment key provisioning uses `ed25519-dalek` 2.2.0 with default features
disabled and only `fast` and `zeroize` enabled, plus `zeroize` 1.8.2. The former
derives Ed25519 public keys from Linux-generated secret seeds; it is not used to
invent a transport protocol. The VM and isolated adapters implement the pinned
TLS profile using their existing OpenSSL implementation. Batch verification,
legacy compatibility, PEM/PKCS#8 parsing, serialization and extra random-number
providers are not enabled by this dependency declaration.

Some packages in the lock and vendor tree support build-time or alternate-target
implementations. Their presence does not mean every module enters the executable.
Licenses retain upstream copyright and conditions; vendoring does not establish
ownership of the code or industrial safety certification.
