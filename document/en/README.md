# Local deployment and supervision

Build with `cargo build --release --locked --offline`. Release builds use optimization level 3, full debug information and checked arithmetic. Rust dependencies and their licenses are included under `third-parties/cargo`.

The [encrypted attachment provisioning contract](attachment-provisioning.md)
describes the Rust key/descriptor handoff primitives and their real-VM tests.
It does not enable native-provider execution in the production CLI.

Every deployed VM requires [kernel device access control](device-isolation.md).
The module also supplies exact-device rules and original-owner reservations for
trusted external provisioners. Native lifecycle integration remains separate.

Use `wros-deployer plan deployment.xml --policy-root /protected/policies` to check bundle paths, pinned Wasm and native driver hashes, budgets and permissions. `wros-deployer review deployment.xml --policy-root /protected/policies` opens a terminal review for each VM. At the edit prompt use `allow NAME`, `deny NAME`, `remove NAME` and `confirm`. An absent recommendation file starts with empty permissions. The explicit `--accept-recommendations` option emits a warning. These commands perform local preflight. `run` additionally admits immutable images and supervises isolated VM processes as described below. Native provider provisioning, live update, the independent watchdog and physical safety integration remain unfinished.

```xml
<deployment id="cell">
  <vm id="body" module="body.wasm" sha256="REPLACE_WITH_64_LOWERCASE_HEX"
      policy="body.policy" recommendations="body-permissions.xml"
      memory-bytes="268435456" pids="8" start-on-boot="false" restart-on-crash="false"/>
  <driver id="joints" file="vendor/driver.so" vendor-version="1.2"
      sha256="REPLACE_WITH_64_LOWERCASE_HEX" hardware-id="cell-arm" kind="shared-library"/>
</deployment>
```

Use a separate file for recommendations. A recommendation exposes an import. Device and resource grants require their own reviewed policies. The current preflight covers interface exposure.

```xml
<recommendations><interface name="abi" expose="allow"/></recommendations>
```

The upstream fetcher resolves vendor URLs. It hands over local artifacts and release digests. The deployer rejects absent files, changed digests and duplicate hardware ownership within a manifest. Vendor code stays in separate processes. Full device exclusivity across deployments requires a trusted platform owner. Systemd is the preferred ultimate supervisor on Linux. A different platform supervisor must provide equivalent restart, user shutdown and resource ownership semantics.

Normal signed execution requires both wasm-cosign and VM verification. The design reserves separate operator warnings for accepting unsigned and invalidly signed modules. Network-facing DDS policies and authenticated local IPC are separate. Motion after a power or authority loss requires independent safety confirmation and human authorization. The recovery state machine performs a cold restart only when approved. Its host ABI remains experimental pending fault tests.

## Verify a signed submission

The XML policy name resolves inside the administrator's independent policy directory. The operator supplies that directory on the command line. Keep the verifier and trust store outside the submitted bundle. Bundle file lookup pins each directory and rejects symlinks. Create a private staging directory owned by the operator with mode 0700.

```sh
wros-deployer verify deployment.xml --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging
```

The deployer copies at most 256 MiB per submitted module, hashes the bytes it copied, and invokes the named wasm-cosign executable on that exact snapshot. It waits up to 30 seconds, checks the exit status, and removes the snapshot on return. The default policy requires a valid signature and matching digest. The execution preview retains the VM's independent signature check. This command finishes before guest execution.

For a specific local development image, `verify` accepts `--allow-unsigned ID=SHA256` or `--allow-invalid-signature ID=SHA256`. Each option applies to one VM and the complete uploaded file digest. A recognized rejection of the matching kind emits a warning and the preview omits secondary verification for that image. A valid signature retains both checks. Unknown verifier failures, missing trust, policy or revocation errors, and a changed upload digest still fail verification.

## Run reviewed VM processes

The `run` command requires a root deployment supervisor and an independently provisioned cgroup v2 subtree. VM instances run as distinct non-root users. The operator reserves those OS users for WROS; the deployer additionally enforces [host-wide identity ownership](host-identities.md) across managers sharing the host registry. It does not allocate OS accounts or restrict unrelated privileged software. Runtime and verifier executables must be protected files outside the submitted bundle. Native driver declarations currently cause `run` to fail before launching any process.

```xml
<deployment id="cell">
  <vm id="body" module="body.wasm" sha256="REPLACE_WITH_64_LOWERCASE_HEX"
      policy="body.policy" vm-policy="body-vm.policy"
      recommendations="body-permissions.xml"
      uid="10001" gid="10001" memory-bytes="268435456" pids="16"
      cpu-micros="100000" restart-on-crash="false"
      restart-limit="3" restart-delay-ms="1000" start-on-boot="false"/>
</deployment>
```

```sh
wros-deployer run deployment.xml --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --cgroup-parent /sys/fs/cgroup/wros.service/workloads
```

The parent cgroup must be an empty domain, owned by root without group/other write access, with finite `memory.max`, zero `memory.swap.max`, and `cpu`, `memory` and `pids` enabled in `cgroup.subtree_control`. It remains owned by the service manager. The deployer creates only its exclusive `wros-DEPLOYMENT/vm-INSTANCE` descendants. Without durable state, a pre-existing deployment directory is rejected, including leftovers from a dead supervisor. The separately locked recovery path below can reclaim only the exact previously approved instance set. The total VM memory reservations must fit the supplied parent. Keep the deployer and ultimate supervisor in separate bounded groups with their own memory headroom. Resource accounting for their images, verification buffers and logs is additional to VM reservations. Linux must support `cgroup.kill`, pidfds, `close_range`, memfd seals and the requested namespaces; unsupported isolation fails before guest execution.

Every child first joins its assigned group, creates network, IPC, UTS, mount and cgroup namespaces, drops supplementary groups and all real/effective/saved IDs, and enables `no_new_privs`. Immutable bytes from the sealed admission image are copied to `/tmp/wros-admitted.wasm` inside a private tmpfs, then the filesystem becomes read-only before guest execution. The tmpfs limit is 257 MiB and its allocated memory is charged to the child's cgroup. The ordinary VM no-follow loader continues to reject symlinks. The underlying executable and admitted source remain pinned. Log pipes are owned by the final guest identity so the VM can reopen its own diagnostics after dropping privileges. Other inherited descriptors close on exec. This isolates resource accounting and selected OS namespaces; it is not a complete filesystem or syscall sandbox.

Normal signed runs use two rollback stores. Initialize `policy` for privileged admission and `vm-policy` for the dedicated VM user, using the official wasm-cosign policy initializer. The policies must have identical trust roots, signer rules, algorithm allowlists, versions and limits; only `state_dir` may differ. Provision the VM state directory and its initialized files with the VM's ownership, directory mode 0700 and file mode 0600. Keep both policy files administrator-owned and readable by the VM. Do not copy a rollback record after changing its policy paths: records bind the policy fingerprint. A fresh deployment needs correctly initialized stores for its actual paths. The VM performs the second verification itself.

The signature exceptions from `verify` also apply to `run`, with an individual digest-bound warning. `--accept-recommendations` bypasses interactive edits only for this invocation and emits its own warning. It does not change signature requirements. The command prints configuration and the full VM argument vector; it does not register a boot service even when XML records boot intent.

## CPU and NUMA placement

An individual `vm` may specify `cpus="2-3,8"` and `memory-nodes="1"`. Both are optional. An omitted attribute inherits the delegated parent's allowed set; an empty attribute is invalid. Lists use ascending decimal indices and disjoint ranges, with no whitespace, signs or leading zeros. Each list is limited to 4096 bytes and every index must be below 8192. Adjacent ranges are normalized before comparison and reporting.

Explicit placement requires `cpuset` in the parent's `cgroup.subtree_control`. The deployer compares every requested set with the parent's `cpuset.cpus.effective` and `cpuset.mems.effective` before creating workloads. Unknown, offline or undelegated resources cause an error. It writes each child's memory-node and CPU constraints and checks the effective values in full. Before every generation starts, it repeats that check and applies the CPU affinity before executing the VM. Guests cannot enlarge their cgroup's allowed CPU or NUMA allocation through affinity or memory-policy system calls. The deployer never enables a controller or expands a set in an ancestor cgroup.

These attributes limit where a workload may execute or allocate memory. They do not reserve exclusive cores, select a real-time scheduler, bind existing shared pages to a node, or guarantee latency. CPU hotplug and administrator changes may alter effective placement after startup. CPU quota can throttle a workload even when its affinity includes several cores. Treat reduced budgets as explicit constraints when qualifying control deadlines. Keep communication peers on separate physical cores when measuring concurrent latency; neighboring logical CPU numbers can be SMT siblings. Isolate interrupt handling and reserve supervisor capacity through the platform service manager when required by the deployment.

## Failure and shutdown semantics

An exit status of zero ends that instance. A failure requests a cold restart only if `restart-on-crash="true"`; at most `restart-limit` restarts occur, separated by `restart-delay-ms`. Defaults are three retries and a one-second delay, but restart remains disabled without the explicit grant. Retry limits range from 0 to 32; delays from 100 to 60000 milliseconds. Each restart has a fresh generation, no motion grant and the same sealed image. All descendants must leave the old cgroup before the new generation starts. CPU quotas use a fixed 100000-microsecond period; `cpu-micros` defaults to 100000 and is an explicitly reported resource constraint.

SIGINT, SIGTERM or SIGHUP stops recovery, requests termination of live instances through pidfds, allows up to two seconds for graceful exit, then kills each remaining descendant cgroup. Diagnostics are drained with bounded per-turn work and capped at 8 KiB per generation. Exit status and memory/task limit events are reported. The control loop polls at five milliseconds; it is not a physical emergency-stop controller. Kernel-uninterruptible tasks still require the ultimate service supervisor to handle incomplete shutdown. A dead deployer triggers a parent-death signal for its direct VM children; an independent systemd or platform service manager must reclaim the entire descendant tree. The optional durable approval described below preserves boot/stop intent and bounded cold-start authority across supervisor death. An external service manager must invoke recovery; automatic service installation and the independent watchdog remain unfinished.

Runtime audit output uses a separate writer and a bounded queue of 32 records, each at most 32 KiB. The supervisor never waits for the log consumer while managing processes. Queue saturation or a writer error stops the deployment. At exit, the writer has at most 500 milliseconds to drain; an incomplete drain produces an unsuccessful invocation after VM shutdown. This prevents a full pipe or a stalled log collector from blocking operator stop. Preflight output occurs before any guest starts.

For a separately bounded manager and whole-tree service shutdown, use [Independent service supervision](service-supervision.md). It adds `authorize` and `service`, followed by `resume --supervisor-cgroup` under the independent supervisor. Authorization does not launch work. Automatic service installation and the strict-MVP watchdog remain unfinished.

## Durable approval and cold starts

Add `--state-directory /protected/state/cell` to an operator-reviewed `run` invocation. The existing directory must be outside the submitted bundle, owned by root, with mode 0700 and protected ancestors. Its regular files have mode 0600 and one hard link. One exclusive lock covers admission, supervision and cleanup. Never share, copy, edit or roll back a live state directory. Each deployment needs its own state directory and delegated workload subtree.

After the complete review and signature checks, the deployer stores the selected import permissions and any exact-digest signature exceptions. This includes decisions accepted through the explicitly warned `--accept-recommendations` option. Automatic invocations reuse that stored decision; they do not reread recommendations or silently accept newly recommended permissions. The binding covers the exact XML bytes, absolute manifest/state/cgroup/policy paths, runtime/verifier/deployer executable hashes and both policy files. Changing those inputs requires a separate operator-reviewed deployment after the previous deployment has safely stopped. This command does not implement live updates.

The ultimate service manager may invoke the following command using the same paths and executables:

```sh
wros-deployer resume /protected/bundles/cell/deployment.xml \
  --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --cgroup-parent /sys/fs/cgroup/wros.service/workloads \
  --state-directory /protected/state/cell
```

`resume` requires matching durable approval. It does not accept `--accept-recommendations` or new signature-waiver options. It repeats signature admission, retains VM verification for normally signed modules, and repeats warnings for a previously approved waiver. The exact uploaded digest still must match. It checks and clears the previously approved cgroup tree before selecting any new work. Unknown child groups or nested groups stop recovery before any kill; unknown or busy leftovers are never attached to as a fresh deployment. A separate process with the same state directory is rejected by the lock.

Within the same kernel boot, a manager crash and a VM crash consume the same `restart-limit`. Only interrupted or faulted instances with `restart-on-crash="true"` can restart. Successful completion, operator stop and a failed/blocked deployment do not restart automatically in that boot. `resume` waits at least the largest configured restart delay among the selected instances; operator stop cancels this wait. An explicit new reviewed `run` may reset retry counts while retaining monotonically increasing generations.

After the kernel boot identity changes, only `start-on-boot="true"` authorizes a cold start. The per-boot retry count resets, but generation numbers continue. As explicitly authorized by this XML setting, a VM stopped before a machine reboot may start on the next boot. Disable the boot grant through a new reviewed deployment when that behavior is unwanted. A crash-restart grant alone does not authorize boot startup. Neither path restores running memory, actuator state or motion authority. Independent safe-state evidence and operator approval remain prerequisites for motion.

The record is bounded to 1 MiB, 128 instances and 256 registered permissions per instance. Before an exec or restart, the deployer writes a new record to a private temporary file, syncs that file, renames it atomically, and syncs the directory. Stop intent is recorded before terminating guests. Truncated or corrupt records, insecure permissions, symlinks, hard links, write failures and disk exhaustion fail closed. The checksum is corruption detection, not an authorization signature. This design assumes correct filesystem durability and a trustworthy administrator; it cannot detect privileged disk rollback. Abandoned `pending-*` files after power loss are never read as authority and may be removed by the administrator while the deployment is stopped.

The journal is on the deployment lifecycle path, not on each ROS/DDS, model or driver message. Durable I/O can be slow or uninterruptible, so it is not a physical emergency-stop mechanism. Systemd or an equivalent independent platform supervisor must still own startup, whole-tree shutdown and bounded restart of the management service. This release neither installs that service nor implements the strict-MVP recovery watchdog. Keep management memory and CPU headroom separate from workload budgets.

## Disposable-kernel qualification

`tests/qemu_supervisor.py` creates a fresh RAM-only Linux guest. It attaches no host disks, no shared filesystem, no physical device and no network. The runner requires the existing 64 GiB, zero-swap gate, caps guest RAM at 4 GiB and uses two emulated CPUs. Supply the official kernel and firmware, built deployer and VM, released wasm-cosign and a fresh `tests/wsea_preflight.py` fixture. Inputs and outcomes are hashed under the requested `.tmp` output directory. The native hostile peer is a test substitute; actual VM checks are separately identified in the receipt. This does not qualify five Linux ABIs, vendor hardware, systemd recovery or industrial safety certification.

Pass `--sdk-module` an actual SDK-built program that calls `uwvm_ros_v2.abi`. The fixture exposes that interface and then denies it, exercising the compiled program through the deployer and VM. `tests/linux_abi.py` separately cross-compiles the Rust implementation and runs its contract tests on x86_64, i686, AArch64, ARM hard float and ARM soft float. These userspace ABI checks do not replace privileged kernel tests on each architecture.

The guest has two NUMA nodes with one virtual CPU and 2 GiB per node. The placement cases verify actual affinity, the allocation node of a touched page, denial of attempts to widen CPU and memory policy, preservation across crash restart, unavailable resources, a narrowed parent, and a missing controller. Two actual VM instances also run with different CPU/node constraints. The suite includes 37 kernel cases, including cross-manager identity conflicts and disjoint concurrent deployment. Userspace contract tests now contain 35 cases per ABI, including attachment key generation, sealed-record and descriptor-injection checks; their receipt binds source files, build configuration and executable hashes. The tests do not assert NUMA performance or hard real-time behavior under emulation.

`tests/qemu_powerloss.py` extends a completed kernel fixture with a new 64 MiB virtual ext4 disk under `.tmp`, two virtual CPUs and 2 GiB RAM. Supply the matching Debian installer kernel-image, ext4 and storage module packages; the harness extracts only selected regular modules into the guest image. No kernel module is loaded on the host. The first QEMU process is killed abruptly after two actual VMs start. Two subsequent fresh boots verify the distinct boot grants, continued generations and persistent operator stop. The last boot fills the virtual disk and checks that failed journal publication preserves the old record and launches no VM. The receipt records three different kernel boot IDs. These tests model a lost guest kernel/process and a full filesystem; they do not prove physical storage cache behavior, hardware stop circuits or platform service-manager recovery.
