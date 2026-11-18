# Provisioning encrypted local attachments

The Rust `attachment` module provisions a dedicated channel for one admitted
VM/provider session. It generates identities, pins already-running process
incarnations and delivers immutable bootstrap objects. It does not launch a
driver, grant hardware access or permit motion. Production native-provider
execution remains disabled in the deployer CLI until resource grants, device
ownership and lifecycle recovery are integrated. The executable under
`tests/support/attachment_provisioner.rs` is a test harness only.

## Admission and delivery

1. The trusted supervisor reserves host identities and resources and establishes
   containment. Each participant has a dedicated final UID/GID, a bounded cgroup
   and pinned namespace membership. Native code never enters the VM process.
2. `endpoints()` obtains two independent 32-byte seeds from Linux `getrandom`.
   It fails if kernel entropy is unavailable; there is no clock/PID seed or weak
   fallback. Ed25519 public keys are derived by pinned `ed25519-dalek` 2.2.0.
   Both keys, including their reciprocal peer pins, are fresh for every channel.
3. Each endpoint receives a sealed 64-byte memfd: its seed followed by the exact
   other endpoint's public key. The memfd has mode 0400 and WRITE, GROW, SHRINK
   and SEAL seals. Temporary seed/record buffers and signing-key objects use
   zeroizing destruction. Kernel memfd storage remains until the last holder
   closes it; this is not a guarantee of physical erasure or protection from
   the privileged host. Secrets never enter XML, argv, environment, logs or Wasm.
4. The carrier is a preconnected, anonymous AF_UNIX SOCK_SEQPACKET pair. Both
   descriptors are nonblocking, close on exec by default and enable SO_PASSCRED
   before any child sends. The supervisor explicitly inherits only the intended
   descriptors into each child. It must not retain another reader/writer after
   handoff. There is no listening address for Wasm or another deployment to select.
5. `Peer::pin` checks exact final real/effective/saved/filesystem UID/GID values,
   retains a pidfd, and opens the actual peer's time namespace. The peer must be
   alive before and after inspection and share the provisioner's monotonic clock.
   Namespace membership must already be pinned by the supervisor; an observed
   namespace inode does not prove which seccomp filter was installed.
6. Once both PIDs are known, the provider bootstrap record binds its local
   identity, peer identity, deployment, VM, module scope, provider generation,
   fresh session, contract digest, finite limits, carrier inode and clock inode.
   The record is sealed before delivery. The VM's corresponding full command-line
   registration uses the same context and descriptors, never private key bytes.
7. The external adapter first sends `WROS-READY` on its private inherited
   bootstrap socket. `deliver` accepts exactly that packet and the approved
   child's kernel credentials. Extra ancillary data, including SCM_RIGHTS,
   is rejected; every received descriptor is closed. It then sends `WROS-FDS`
   and exactly four descriptors in this order: carrier, identity, peer clock,
   bootstrap record. There is a finite deadline, at most five seconds, and no
   retry with weaker authentication. This kernel-confined descriptor handoff is
   trust initialization, not an application plaintext service.
8. The adapter checks the provisioner's credentials, exact descriptor count and
   the VM repository's `provider_bootstrap::load` result, closes the courier, and
   starts the existing bound mutual-TLS handshake. The record is not a grant.
   Readiness and successful TLS do not authorize any operation or prove a safe
   physical state. Both VM permissions and independent receiver admission remain
   mandatory. Close the original descriptors once their validated state has
   been consumed; the channel owns its required private duplicates.

The current cryptographic profile is TLS 1.3 with exact Ed25519 raw-public-key
pins, ephemeral X25519 and AES-128-GCM. The deployment/VM/scope/provider/session
identifiers and contract digest are committed through the TLS transcript label.
Unknown profile codes are rejected. A future profile needs explicit implementation
and policy admission at both ends; its code is not permission to negotiate a
weaker fallback. Runtime packets remain encrypted and kernel-credential checked.

## Fixed driver bootstrap record

The record is exactly 256 bytes. All scalar fields are unsigned 64-bit
little-endian values. There is no native struct serialization or pointer.
Opaque identifiers and digests retain their byte order in the VM registration.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | Magic bytes `WROSDRV` followed by NUL |
| 8 | 8 | Exact record length, 256 |
| 16 | 8 | Service, 1 for driver |
| 24 | 8 | Cryptographic profile, 1 for the profile above |
| 32 | 24 | Adapter PID, UID and GID |
| 56 | 24 | VM PID, UID and GID |
| 80 | 80 | Deployment, VM, scope, provider and session; 16 bytes each |
| 160 | 32 | Contract SHA-256 |
| 192 | 32 | Request bytes, response bytes, request nanoseconds, session expiry |
| 224 | 16 | Adapter carrier's kernel device and inode |
| 240 | 16 | Peer time namespace's kernel device and inode |

Request and response limits are each 1–65536 bytes. Time bounds are nonzero and
at most INT64_MAX; expired sessions fail before TLS. PIDs are positive signed
32-bit values, the two processes must differ, and invalid all-ones UIDs/GIDs are
rejected. Every identity and the digest must be nonzero. The decoder publishes
output only after the complete record is valid. Loading additionally verifies
seals, descriptor types, exact file sizes, local credentials and object inodes.
The regular channel binding still validates the clock namespace type and identity,
pidfd liveness, socket properties and every packet's credentials.

The bootstrap contains no command, path, FFI address, executable image, file grant,
signal, restart or update operation. Changing a provider generation requires
new admission and fresh channels; a connected Wasm module cannot do it.

## Qualification and limits

`tests/attachment_provisioning.py` builds optimized binaries with debug symbols
and runs an actual VM against a separate C++ harmless-query receiver. It checks
successful delivery, wrong key, wrong session binding, descriptor substitution,
unknown profile, malformed readiness, peer death, unexpected descriptor transfer
and readiness from another process. It also checks parent descriptor counts.
`tests/attachment_protocol_abis.py` executes the fixed decoder on five Linux ABIs
and under ASan/UBSan. `tests/linux_abi.py` exercises the Rust key generation and
existing deployer contracts on those ABIs.

`tests/qemu_attachment_provisioning.py` repeats real-VM attachment cases with
different non-root identities, separate network namespaces and separate nested
cgroups in an offline disposable kernel. The guest has no physical device, host
disk or shared-folder access. All test work remains inside the host's existing
64 GiB zero-swap cgroup. These tests do not qualify arbitrary vendor binaries,
physical stop behavior, device exclusivity or industrial safety certification.

Provisioning runs once per admitted session. Key generation, memfd sealing and
bootstrap parsing are not inserted into the per-message call path. Do not add
startup measurements to a native/Wasm round-trip comparison or describe this
test harness as the finished production deployer.

The qualification runners verify the actual OpenSSL archive digests and their
build receipts, as well as the VM's compile and link commands. The cryptographic
dependency must also use `-O3 -g`; debug symbols on only the calling program are
insufficient for source and assembly attribution. Hardware sampling measures
long repeated workloads. Its event period is not a guarantee that each sample
arrives at a fixed wall-clock interval.
