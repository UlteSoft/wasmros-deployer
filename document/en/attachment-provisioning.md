# Provisioning encrypted local attachments

The Rust `attachment` module provisions a dedicated channel for one admitted
VM/provider session. It generates identities, pins already-running process
incarnations and delivers immutable bootstrap objects. The production `run`
path provisions one independently authenticated session per driver executable declaration. Each declaration selects one VM. Multiple providers for that VM use distinct aliases, UIDs, GIDs, cgroups and disjoint sandbox roots. Their VM-side reservations share the VM XML attribute `driver-budget-bytes`. Each provider must also fit its own memory budget. The provider
receives its ID as argv[0], then the courier FD, manager PID, manager UID,
manager GID and the literal `read-only`. The separate executable under
`tests/support/attachment_provisioner.rs` exercises handoff edge cases.

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
8. The adapter uses the VM repository's host-only
   `provider_bootstrap_receiver.h`. Its `receive` operation sends readiness,
   pins the provisioner with a pidfd, checks the kernel credentials and exact
   descriptor count, and calls `provider_bootstrap::load`. It publishes the
   descriptor bundle and record only after complete validation. The adapter
   closes the courier and starts the existing bound mutual-TLS handshake. The record is not a grant.
   Readiness and successful TLS do not authorize any operation or prove a safe
   physical state. Both VM permissions and independent receiver admission remain
   mandatory. Close the original descriptors once their validated state has
   been consumed; the channel owns its required private duplicates.

The receiver borrows its courier, preserves the descriptor's flags and options,
and accepts a local timeout of 1–5,000,000,000 nanoseconds. It rejects an output
bundle that already owns descriptors. Failed or truncated handoffs close every
received descriptor, including excess SCM_RIGHTS entries. Both bootstrap ends
use bounded ancillary storage covering the complete Linux maximum of 253
descriptors, then explicitly close and reject all unrequested handles. They do
not depend on a userspace emulator discarding truncated ancillary handles.
The noncopyable
`descriptors` bundle owns the four admitted objects; its accessors borrow them,
and `reset()` closes them after channel initialization. The expected provisioner
PID/UID/GID must come from trusted launch state. Reading that identity from the
delivery itself would defeat authentication. This receiver performs no heap
allocation and is used only in the separate adapter, not compiled into the VM.

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
and under ASan/UBSan. Its `--suite receiver` selects 19 kernel handoff cases,
including credential impersonation, maximum-size descriptor injection, object substitution,
missing seals, expired records, invalid courier configuration and bounded timeout.
Those cases check actual descriptor counts and unchanged output after refusal.
`tests/linux_abi.py` exercises the Rust key generation and
existing deployer contracts on those ABIs.

`tests/qemu_attachment_provisioning.py` repeats real-VM attachment cases with
different non-root identities, separate network namespaces and separate nested
cgroups in an offline disposable kernel. The test provisioner installs the fixed
[device baseline](device-isolation.md) on both empty groups before either peer
starts. Each scenario uses fresh groups; an existing policy is never replaced.
This tests encrypted IPC under kernel device restrictions, not vendor hardware
grants. The guest has no physical device, host disk or shared-folder access.
All test work remains inside the host's existing
64 GiB zero-swap cgroup. These tests do not qualify arbitrary vendor binaries,
physical stop behavior, device exclusivity or industrial safety certification.
Pass `--receiver-checks` with the native receiver boundary fixture to additionally
run its 19 cases inside that kernel. The Rust contract suite separately verifies
that all 253 injected descriptors in a readiness packet are closed on rejection.
That component test supplies controlled clock evidence while exercising real
pidfds and descriptor transfer. Namespace-type admission remains a separate
full-kernel test: the user-mode emulator's missing namespace ioctl is rejected
by production code, never treated as permission to skip validation.

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

### Unitree Go2 native telemetry

`tests/vendor_unitree_qemu.py` uses a local Unitree SDK 2.0.2 archive with a pinned
SHA-256. The offline guest runs the upstream HelloWorld pair and exchanges Go2
`LowState` through the release's native DDS libraries. The fixture signs the staged
executables and libraries with a disposable Ed25519 key. The guest verifies the
manifest and rejects a modified copy before starting the native processes.

The optional attachment inputs add a `wrwat` guest with WasmMTE enabled. The
signer uses one disposable P-384 key to produce both the WSEA module signature
and the Linux CMS signature on the native provider. Supply Linux's `scripts/sign-file`
through `--sign-file`. The deployer verifies both artifacts and the VM checks the
Wasm again with independent rollback state. The Rust test provisioner passes fresh TLS credentials and sealed
bootstrap descriptors to separate non-root processes. The Go2 adapter reads a
single joint sample from the official SDK and exposes only that bounded read.
The VM, adapter, and loopback-only DDS writer have distinct cgroups. The
interpreter and AOT engine both check the DDS sample in Wasm. Additional cases
require explicit rejection of modified Wasm bytes and a mismatched peer key.

Use `--help` for the full attachment and QEMU inputs. Select a private
`--signing-scratch` under the VM's disk-backed `.tmp`, and run the test inside a
64 GiB cgroup with zero swap. The results record the upstream archive, executable
and compiler input hashes, the selected engine, and guest checks. The publisher
generates fixed telemetry in the test guest. Physical Go2 and production driver
startup are separate acceptance gates.

`tests/vendor_unitree_mujoco.py` exercises the separate simulation path. It
loads the pinned official Go2 model and Unitree's original Python DDS bridge
under MuJoCo 3.4.0. An independently built native SDK subscriber and the pinned
official Python SDK both verify joint position, IMU quaternion and base position.
The replay signs the simulator and both readers' staged inputs and checks the
signature before running inside a loopback-only network namespace. It runs
headless with joystick input disabled. Use `--help` to supply the model and its
provenance, the two pinned bridge files, the local SDK sources and the Python
dependency directory. Install the Cyclone DDS 0.10.2 Python binding against the
SDK's native Cyclone library. Set the dependency directory to one containing
MuJoCo 3.4.0, NumPy and Pygame for the selected Python executable.

[Unitree SDK 2.0.2](https://github.com/unitreerobotics/unitree_sdk2/releases/tag/v2.0.2) ·
[Unitree MuJoCo bridge](https://github.com/unitreerobotics/unitree_mujoco/tree/1eb6642e3f3fdfb7fb13a9794fd6a2dd93ea0e7d)

### Universal Robots Client Library

`tests/vendor_universal_robots.py` verifies the local Universal Robots Client
Library 2.16.0 and GoogleTest 1.17.0 archives and builds the upstream offline
suite with optimization and debug line information. The runner signs the
compiled test binaries, libraries and CTest plan with a throwaway Ed25519 key.
It verifies their hashes before each executable runs in a fresh loopback-only
network namespace. Independent namespaces prevent earlier tests from occupying
the hardcoded ports of later tests.

The offline suite covers 673 registered cases, including RTDE negotiation and
telemetry, reconnects, command serialization, primary and dashboard protocol
handling, and trajectory interfaces. The receipt tracks every test name, status
and signed file digest. The same runner accepts `--suite rtde` for the focused
parser and RTDE client suite. URSim and the ROS hardware driver require their
own integration runs with the matching controller version.

```sh
systemd-run --user --scope -p MemoryMax=64G -p MemorySwapMax=0 \
  python3 -B tests/vendor_universal_robots.py \
  --archive "$PWD/.tmp/urcl-2.16.0.tar.gz" \
  --gtest-archive "$PWD/.tmp/googletest-1.17.0.tar.gz" \
  --output "$PWD/.tmp/urcl-offline"
```

[Universal Robots Client Library 2.16.0](https://github.com/UniversalRobots/Universal_Robots_Client_Library/releases/tag/2.16.0)
