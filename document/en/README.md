# Local deployment and supervision

Build with `cargo build --release --locked --offline`. Release builds use optimization level 3, full debug information and checked arithmetic. Rust dependencies and their licenses are included under `third-parties/cargo`.

To review workloads and per-VM permission files from one XML entry, see [Deploying a bundle from one XML file](configuration-dependencies.md).

The [encrypted attachment provisioning contract](attachment-provisioning.md)
describes the Rust key/descriptor handoff primitives and their real-VM tests.
The production CLI uses these primitives for explicitly reviewed read-only native providers.

Every deployed VM requires [kernel device access control](device-isolation.md).
The module also supplies exact-device rules and original-owner reservations for
trusted external provisioners. Native lifecycle integration remains separate.

Use `wros-deployer plan deployment.xml --policy-root /protected/policies` to check bundle paths, pinned Wasm and native driver hashes, budgets and permissions. `wros-deployer review deployment.xml --policy-root /protected/policies` opens a terminal review for each VM. At the edit prompt use `allow NAME`, `deny NAME`, `remove NAME`, `hide abi` or `hide permission.report`, then `confirm`. An absent recommendation file starts with no recommended grants. Use `show` to see updated scores and `cancel` to leave the review. The pair `--accept-recommendations-through-risk --risk-accept-threshold default` adopts scored recommendations through 3/10. Higher and unassessed recommendations require individual decisions. Use an explicit integer from 0 through 10 to choose another ceiling. The effective decisions and configured risk report are still displayed. These commands perform local preflight. `run` additionally admits immutable images and supervises isolated VM processes as described below. Native provider recovery, live update, the independent watchdog and physical safety integration remain unfinished.

```xml
<deployment id="cell">
  <vm id="body" module="body.wasm" sha256="REPLACE_WITH_64_LOWERCASE_HEX"
      policy="body.policy" recommendations="body-permissions.xml"
      memory-bytes="268435456" pids="8" start-on-boot="false" restart-on-crash="false"/>
  <driver id="joints" file="vendor/driver.so" vendor-version="1.2"
      sha256="REPLACE_WITH_64_LOWERCASE_HEX" hardware-id="cell-arm" kind="shared-library"
      elf-signer="vendor-publisher.pem"/>
</deployment>
```

Use a separate file for recommendations. A recommendation exposes an import. Device and resource grants require their own reviewed policies. The current preflight covers interface exposure.

```xml
<recommendations><interface name="abi" expose="allow"/></recommendations>
```

The upstream fetcher resolves vendor URLs. It hands over local artifacts and release digests. The deployer rejects absent files, changed digests and duplicate hardware ownership within a manifest. Vendor code stays in separate processes. Full device exclusivity across deployments requires a trusted platform owner. Systemd is the preferred ultimate supervisor on Linux. A different platform supervisor must provide equivalent restart, user shutdown and resource ownership semantics.

Normal signed execution requires both wasm-cosign and VM verification. The design reserves separate operator warnings for accepting unsigned and invalidly signed modules. Network-facing DDS policies and authenticated local IPC are separate. Motion after a power or authority loss requires independent safety confirmation and human authorization. The recovery state machine performs a cold restart only when approved. Its host ABI remains experimental pending fault tests.

## Verify a signed submission

The XML policy name resolves inside the administrator's independent policy directory. The operator supplies that directory on the command line. Keep the verifier and trust store outside the submitted bundle. Manifest and artifact reads use the same pinned bundle directory. Artifact lookup rejects symlink components and checks the final inode type before opening any contents. Only regular files are read. Create a private staging directory owned by the operator with mode 0700.

```sh
wros-deployer verify deployment.xml --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging
```

The deployer copies at most 256 MiB per submitted module, hashes the bytes it copied, and invokes the named wasm-cosign executable on that exact snapshot. It waits up to 30 seconds, checks the exit status, and removes the snapshot on return. The default policy requires a valid signature and matching digest. The execution preview retains the VM's independent signature check. This command finishes before guest execution.

For a specific local development image, `verify` accepts `--allow-unsigned ID=SHA256` or `--allow-invalid-signature ID=SHA256`. Each option applies to one VM and the complete uploaded file digest. A recognized rejection of the matching kind emits a warning and the preview omits secondary verification for that image. A valid signature retains both checks. Unknown verifier failures, missing trust, policy or revocation errors, and a changed upload digest still fail verification.

The CLI prints one INFO line for each reviewed ROSv2 interface and its allow or deny decision. An empty review is shown explicitly. Interface exposure and permission to use a particular resource are separate decisions.

### Verify signed ELF drivers

For a submission listing native drivers, add `--elf-verifier /opt/wros/bin/uwvm2-ros` to `verify`. The driver's `elf-signer` identifies a PEM X.509 certificate under the administrator's `--policy-root`. The deployer hashes the entire shipped ELF and invokes `uwvm2-ros --verify-elf-driver KIND ELF SIGNER.pem` on the private snapshot. The verifier checks the Linux appended CMS envelope, pinned signer, certificate validity, digest strength and host ELF ABI, then exits.

The publisher can use one P-384 private key and certificate for both kinds of release. Sign the Wasm with `cosign wasm secure sign` and `--algorithm ES384`, using its WSEA policy and CRL. Sign the final ELF and record the complete signed file digest.

```sh
scripts/sign-file sha384 publisher.key publisher.pem driver.so driver.signed.so
sha256sum driver.signed.so
```

Unsigned and invalidly signed ELFs fail by default. In `verify` and explicit `run`, `--allow-unsigned-elf DRIVER=SHA256` and `--allow-invalid-elf-signature DRIVER=SHA256` select separate, digest-bound exceptions and emit warnings. Specify an exception separately for each affected driver ID even when drivers use identical bytes. Wasm exceptions likewise require a decision for each VM ID. Malformed envelopes, missing trust and unknown verifier errors fail even with an exception. Administrators must remove revoked or compromised certificates from the pinned ELF trust store.

### Launch a read-only native provider

Add an attachment inside the driver's `<driver kind="executable" ...>` element.

```xml
<attachment vm="body" alias="joints" sandbox="go2" uid="24002" gid="24002"
    contract-sha256="REPLACE_WITH_64_LOWERCASE_HEX"
    memory-bytes="268435456" pids="32" cpu-micros="100000"/>
```

On each `<attachment>`, `request-bytes` and `response-bytes` set independent authenticated payload ceilings. Omitting either selects 32 bytes for that direction. The wire protocol supports 65,536 payload bytes in each direction, separately from its 176-byte header. The `buffer.read` request contains three 64-bit words. Its result starts with an eight-byte length, so a 4,096-byte payload budget carries up to 4,088 bytes of sensor data. The deployer displays both limits. A ceiling above 32 bytes has a review score of 6/10. The operator can confirm that attachment individually or adopt it with the paired risk switches at a threshold of 6 or higher. Final deployment confirmation still binds the exact manifest. The approved manifest digest covers both numbers. The VM and native provider receive the same limits through their channel configuration and authenticated bootstrap.

Supply `--driver-root /protected/provider-roots` and `--elf-verifier /opt/wros/bin/uwvm2-ros` to `run` along with the VM options below. The administrator provisions `/protected/provider-roots/go2` with the reviewed loader, libraries, configuration and an empty `proc` directory for a read-only process view. The mount uses `hidepid=2,subset=pid` and preserves access to the provider's own executable and time namespace. Installation must preserve root ownership and deny group and other write access. The deployer mounts this tree read-only, delivers a connected business attachment and grants zero physical devices. Vendor shared libraries run through a signed executable adapter in that root. Each provider has a distinct non-root UID, GID and cgroup. Its executable implements the inherited descriptor handshake in [attachment provisioning](attachment-provisioning.md).

Review `capability.open`, `driver.connect`, `driver.submit`, `driver.result` and `driver.disconnect` separately from the resource decision `driver/joints/buffer.read`. The recommendation XML can propose the resource decision with `<driver-resource alias="joints" operation="buffer.read" access="allow"/>`. This profile accepts one attached provider per VM and uses the bounded `buffer.read` wire schema.

The deployer hashes and seals the complete signed ELF before initial verification, repeats verification of the same bytes immediately before launch, and executes that inode with `execveat`. The second decision must match the first. A withdrawn or changed signer aborts launch. Native execution requires an explicit operator run. Automatic start, restart and service mode remain for VM-only deployments.

## Run reviewed VM processes

The `run` command requires a root deployment supervisor and an independently provisioned cgroup v2 subtree. VM instances and providers run with distinct non-root identities. The operator reserves those OS identities for WROS. The deployer enforces [host-wide identity ownership](host-identities.md) across managers sharing the registry. Runtime and verifier executables must be protected files outside the submitted bundle.

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

The parent cgroup must be an empty domain, owned by root without group/other write access, with finite `memory.max`, zero `memory.swap.max`, and `cpu`, `memory` and `pids` enabled in `cgroup.subtree_control`. It remains owned by the service manager. The deployer creates its exclusive `wros-DEPLOYMENT` tree with separate VM and driver children. Without durable state, a pre-existing deployment directory is rejected, including leftovers from a dead supervisor. The separately locked recovery path below can reclaim only the exact previously approved instance set. The aggregate VM and driver memory reservations must fit the supplied parent. Keep the deployer and ultimate supervisor in separate bounded groups with their own memory headroom. Resource accounting for their images, verification buffers and logs is additional to VM reservations. Linux must support `cgroup.kill`, pidfds, `close_range`, memfd seals and the requested namespaces; unsupported isolation fails before guest execution.

Every child first joins its assigned group, creates network, IPC, UTS, mount and cgroup namespaces, drops supplementary groups and all real/effective/saved IDs, and enables `no_new_privs`. Immutable bytes from the sealed admission image are copied to `/tmp/wros-admitted.wasm` inside a private tmpfs, then the filesystem becomes read-only before guest execution. The tmpfs limit is 257 MiB and its allocated memory is charged to the child's cgroup. The ordinary VM no-follow loader continues to reject symlinks. The underlying executable and admitted source remain pinned. Log pipes are owned by the final guest identity so the VM can reopen its own diagnostics after dropping privileges. Other inherited descriptors close on exec. This isolates resource accounting and selected OS namespaces; it is not a complete filesystem or syscall sandbox.

Normal signed runs use two rollback stores. Initialize `policy` for privileged admission and `vm-policy` for the dedicated VM user, using the official wasm-cosign policy initializer. The policies must have identical trust roots, signer rules, algorithm allowlists, versions and limits; only `state_dir` may differ. Provision the VM state directory and its initialized files with the VM's ownership, directory mode 0700 and file mode 0600. Keep both policy files administrator-owned and readable by the VM. Do not copy a rollback record after changing its policy paths: records bind the policy fingerprint. A fresh deployment needs correctly initialized stores for its actual paths. The VM performs the second verification itself.

The signature exceptions from `verify` also apply to `run`, with an individual digest-bound warning. The terminal editor shows the available decisions for every VM. By default, confirm each VM after editing its permissions. Both risk-acceptance options are required for bounded adoption. In either mode, review the effective decisions and exact arguments, then type `deploy DEPLOYMENT_ID` to start. A closed terminal or missing confirmation stops the launch. The command prints configuration and the full VM argument vector; it does not register a boot service even when XML records boot intent.

Every production VM runs inside a private read-only root. The deployer binds validated immutable system library trees, the exact WSEA policy and trust root, and the VM-owned mode-0700 rollback directory. Four kernel-filtered pseudo-devices and a read-only, PID-filtered procfs support the runtime. Other host paths, shared memory directories and host FIFOs are absent. Managed processes inherit only standard streams and the descriptors required for their role. A trusted script runtime also retains its script descriptor for its interpreter.

Workload seccomp permanently denies new socket endpoints, io_uring, named IPC creation, cross-process memory and descriptor inspection. Each VM and driver has separate network and IPC namespaces. Both roles reject filesystem notification watches. Native drivers also reject advisory locks and leases on shared inodes. The trusted VM uses file locks in its private WSEA rollback directory. An approved driver attachment remains usable through its connected socket, kernel peer credentials and mutual TLS. Drivers needing a new DDS or other socket at runtime require a provisioned business transport. No manifest permission, threshold or terminal edit opens a management listener. The fixed VM arguments include `--debug-permissions none --debug-dump-force none`. The deployer supplies no debugger, dump or live-update controller to a workload.

Each managed VM starts with `--runtime-memtag-mode sync` and
`--runtime-memtag-action crash`. A detected tag mismatch terminates the VM at
the fault. A guest built without WasmMTE instructions or tag metadata continues
to run ordinary Wasm with its normal bounds checks.

The review scores observed permissions from 0 to 10. Read-only clocks score 0,
while controls with potential hardware effects and digest-bound signature
exceptions receive high scores. `UNASSESSED` indicates missing assessment
evidence. Scores describe the effect of granting an operation and confer no
authority. The review shows overlapping explicit CPU and NUMA placement and
shared native sandbox paths. It inventories import declarations from the
digest-bound Wasm. Imported namespaces identify a link interface and may be
host services. Preloaded Wasm libraries require explicit dependencies, pinned images and independent signature policies. The manifest grants no arbitrary host mounts or folders.

In-process native preload requests score 10 and are refused, including
`--wasm-register-dl` and its `-Wdl` alias. The separate `report/preloaddl` decision
only controls whether an authorized guest can read the VM's native preload
build status. This decision never loads a library. The production VM omits
native preload. A signed isolated ELF provider uses separate admission.

The deprecated `uwvm_ros1_v1.abi_version` and `uwvm_ros2_v1.abi_version`
keys each expose only their named version query. Use them only with a VM
explicitly built with that version's legacy ABI. If the ABI is absent, the VM
refuses the resulting launch flags. Neither key supplies a gateway, data
access, or another legacy interface.

## CPU and NUMA placement

An individual `vm` may specify `cpus="2-3,8"` and `memory-nodes="1"`. Both are optional. An omitted attribute inherits the delegated parent's allowed set; an empty attribute is invalid. Lists use ascending decimal indices and disjoint ranges, with no whitespace, signs or leading zeros. Each list is limited to 4096 bytes and every index must be below 8192. Adjacent ranges are normalized before comparison and reporting.

Explicit placement requires `cpuset` in the parent's `cgroup.subtree_control`. The deployer compares every requested set with the parent's `cpuset.cpus.effective` and `cpuset.mems.effective` before creating workloads. Unknown, offline or undelegated resources cause an error. It writes each child's memory-node and CPU constraints and checks the effective values in full. Before every generation starts, it repeats that check and applies the CPU affinity before executing the VM. Guests cannot enlarge their cgroup's allowed CPU or NUMA allocation through affinity or memory-policy system calls. The deployer never enables a controller or expands a set in an ancestor cgroup.

These attributes limit where a workload may execute or allocate memory. They do not reserve exclusive cores, select a real-time scheduler, bind existing shared pages to a node, or guarantee latency. CPU hotplug and administrator changes may alter effective placement after startup. CPU quota can throttle a workload even when its affinity includes several cores. Treat reduced budgets as explicit constraints when qualifying control deadlines. Keep communication peers on separate physical cores when measuring concurrent latency; neighboring logical CPU numbers can be SMT siblings. Isolate interrupt handling and reserve supervisor capacity through the platform service manager when required by the deployment.

## Failure and shutdown semantics

An exit status of zero ends that instance. A failure requests a cold restart only if `restart-on-crash="true"`; at most `restart-limit` restarts occur, separated by `restart-delay-ms`. Defaults are three retries and a one-second delay, but restart remains disabled without the explicit grant. Retry limits range from 0 to 32; delays from 100 to 60000 milliseconds. Each restart has a fresh generation, no motion grant and the same sealed image. All descendants must leave the old cgroup before the new generation starts. CPU quotas use a fixed 100000-microsecond period; `cpu-micros` defaults to 100000 and is an explicitly reported resource constraint.

SIGINT, SIGTERM or SIGHUP stops recovery, requests termination of live instances through pidfds, allows up to two seconds for graceful exit, then kills each remaining descendant cgroup. Diagnostics are drained with bounded per-turn work and capped at 8 KiB per generation. Exit status and memory/task limit events are reported. The control loop polls at five milliseconds; it is not a physical emergency-stop controller. Kernel-uninterruptible tasks still require the ultimate service supervisor to handle incomplete shutdown. A dead deployer triggers a parent-death signal for its direct VM children; an independent systemd or platform service manager must reclaim the entire descendant tree. The optional durable approval described below preserves boot/stop intent and bounded cold-start authority across supervisor death. An external service manager must invoke recovery; automatic service installation and the independent watchdog remain unfinished.

Runtime audit output uses a separate writer and a bounded queue of 32 records, each at most 32 KiB. The supervisor never waits for the log consumer while managing processes. Queue saturation or a writer error stops the deployment. At exit, the writer has at most 500 milliseconds to drain; an incomplete drain produces an unsuccessful invocation after VM shutdown. This prevents a full pipe or a stalled log collector from blocking operator stop. Preflight output occurs before any guest starts.

The supervisor gives the direct VM processes a shared two-second grace period after sending SIGTERM. It then writes to the deployment's dedicated `cgroup.kill` to stop all remaining descendants together. The tree and direct children share a single two-second settling budget. A populated group or unreaped child after that budget produces a failure for the outer supervisor. This is a software wait budget. Kernel scheduling, uninterruptible tasks and a blocked storage commit can prevent a wall-clock guarantee. [Kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files)

For a separately bounded manager and whole-tree service shutdown, use [Independent service supervision](service-supervision.md). It adds `authorize` and `service`, followed by `resume --supervisor-cgroup` under the independent supervisor. Authorization does not launch work. Automatic service installation and the strict-MVP watchdog remain unfinished.

## Durable approval and cold starts

Add `--state-directory /protected/state/cell` to an operator-reviewed `run` invocation. The existing directory must be outside the submitted bundle, owned by root, with mode 0700 and protected ancestors. Its regular files have mode 0600 and one hard link. One exclusive lock covers admission, supervision and cleanup. Never share, copy, edit or roll back a live state directory. Each deployment needs its own state directory and delegated workload subtree.

After the complete review and signature checks, the deployer stores the selected import permissions and any exact-digest signature exceptions. Automatic invocations reuse that stored decision; they do not reread recommendations or silently accept newly recommended permissions. The binding covers the exact XML bytes, absolute manifest/state/cgroup/policy paths, runtime/verifier/deployer executable hashes and both policy files. Changing those inputs requires a separate operator-reviewed deployment after the previous deployment has safely stopped. This command does not implement live updates.

The ultimate service manager may invoke the following command using the same paths and executables:

```sh
wros-deployer resume /protected/bundles/cell/deployment.xml \
  --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --cgroup-parent /sys/fs/cgroup/wros.service/workloads \
  --state-directory /protected/state/cell
```

`resume` requires matching durable approval. It reuses the exact approved decisions. Review-time acceptance switches and new signature waivers are rejected. It repeats signature admission, retains VM verification for normally signed modules, and repeats warnings for a previously approved waiver. The exact uploaded digest still must match. It checks and clears the previously approved cgroup tree before selecting any new work. Unknown child groups or nested groups stop recovery before any kill; unknown or busy leftovers are never attached to as a fresh deployment. A separate process with the same state directory is rejected by the lock.

Within the same kernel boot, a manager crash and a VM crash consume the same `restart-limit`. Only interrupted or faulted instances with `restart-on-crash="true"` can restart. Successful completion, operator stop and a failed/blocked deployment do not restart automatically in that boot. `resume` waits at least the largest configured restart delay among the selected instances; operator stop cancels this wait. An explicit new reviewed `run` may reset retry counts while retaining monotonically increasing generations.

After the kernel boot identity changes, only `start-on-boot="true"` authorizes a cold start. The per-boot retry count resets, but generation numbers continue. As explicitly authorized by this XML setting, a VM stopped before a machine reboot may start on the next boot. Disable the boot grant through a new reviewed deployment when that behavior is unwanted. A crash-restart grant alone does not authorize boot startup. Neither path restores running memory, actuator state or motion authority. Independent safe-state evidence and operator approval remain prerequisites for motion.

The record is bounded to 1 MiB, 128 instances and 256 registered permissions per instance. Before an exec or restart, the deployer writes a new record to a private temporary file, syncs that file, renames it atomically, and syncs the directory. Stop intent is recorded before terminating guests. Truncated or corrupt records, insecure permissions, symlinks, hard links, write failures and disk exhaustion fail closed. The checksum is corruption detection, not an authorization signature. This design assumes correct filesystem durability and a trustworthy administrator; it cannot detect privileged disk rollback. Abandoned `pending-*` files after power loss are never read as authority and may be removed by the administrator while the deployment is stopped.

The journal is on the deployment lifecycle path, not on each ROS/DDS, model or driver message. Durable I/O can be slow or uninterruptible, so it is not a physical emergency-stop mechanism. Systemd or an equivalent independent platform supervisor must still own startup, whole-tree shutdown and bounded restart of the management service. This release neither installs that service nor implements the strict-MVP recovery watchdog. Keep management memory and CPU headroom separate from workload budgets.

## Disposable-kernel qualification

`tests/qemu_supervisor.py` creates a fresh RAM-only Linux guest. It attaches no host disks, no shared filesystem, no physical device and no network. The runner requires the existing 64 GiB, zero-swap gate, caps guest RAM at 4 GiB and uses two emulated CPUs. Supply the official kernel and firmware, built deployer and VM, released wasm-cosign and a fresh `tests/wsea_preflight.py` fixture. Inputs and outcomes are hashed under the requested `.tmp` output directory. The native hostile peer is a test substitute; actual VM checks are separately identified in the receipt. This does not qualify five Linux ABIs, vendor hardware, systemd recovery or industrial safety certification.

Pass `--sdk-module` an actual SDK-built program that calls `uwvm_ros_v2.abi`. The fixture exposes that interface and then denies it, exercising the compiled program through the deployer and VM. `tests/linux_abi.py` separately cross-compiles the Rust implementation and runs its contract tests on x86_64, i686, AArch64, ARM hard float and ARM soft float. These userspace ABI checks do not replace privileged kernel tests on each architecture.

The guest has two NUMA nodes with one virtual CPU and 2 GiB per node. The placement cases verify actual affinity, the allocation node of a touched page, denial of attempts to widen CPU and memory policy, preservation across crash restart, unavailable resources, a narrowed parent, and a missing controller. Two actual VM instances also run with different CPU/node constraints. The suite includes 37 kernel cases, including cross-manager identity conflicts and disjoint concurrent deployment. Userspace contract tests now contain 35 cases per ABI, including attachment key generation, sealed-record and descriptor-injection checks; their receipt binds source files, build configuration and executable hashes. The tests do not assert NUMA performance or hard real-time behavior under emulation.

`tests/qemu_powerloss.py` extends a completed kernel fixture with a new 64 MiB virtual ext4 disk under `.tmp`, two virtual CPUs and 2 GiB RAM. Supply the matching Debian installer kernel-image, ext4 and storage module packages; the harness extracts only selected regular modules into the guest image. No kernel module is loaded on the host. The first QEMU process is killed abruptly after two actual VMs start. Two subsequent fresh boots verify the distinct boot grants, continued generations and persistent operator stop. The last boot fills the virtual disk and checks that failed journal publication preserves the old record and launches no VM. The receipt records three different kernel boot IDs. These tests model a lost guest kernel/process and a full filesystem; they do not prove physical storage cache behavior, hardware stop circuits or platform service-manager recovery.

For the disposable 4 GiB QEMU supervisor test, choose the SDK application's guest memory budget with `--sdk-memory-bytes BYTES`. The default is 256 MiB. Embedded language runtimes can require more memory during module loading and compilation. The selected budget applies to the SDK allow/deny cases and is recorded in the result. A kernel OOM during the allow case fails the test.

Each VM can select its execution engine with the XML attribute `engine="aot"` (default) or `engine="interpreter"`. The review prints the selected engine, and the launch record contains the full VM option. Both engines use the same reviewed import and resource permissions. Measure startup time and memory inside the intended device cgroup. The QEMU test accepts the same selection with `--sdk-engine`.

A VM with the AOT engine can set `aot-policy="fast-compile"` to favor cold startup, or select `default`, `balanced` or `max`. Review prints the choice, and execution includes the full `--runtime-llvm-jit-policy` argument. Measure cold start and steady-state performance with the actual application and CPU budget.

The full-kernel test checks three permission outcomes. The SDK guest runs with the ABI inquiry granted. With an explicit denial, a dedicated Wasm probe checks the numeric return value 13. Omitting the import from the recommendation causes the VM to reject the SDK guest before entry.

To include the signed application itself, pass its unsigned core Wasm to the test authority using `tests/wsea_preflight.py --sdk-module FILE --sdk-source TRUSTED_SDK_CHECKOUT`. Pass the resulting `bundle/sdk.signed.wasm` to `tests/qemu_supervisor.py --signed-sdk-module` in addition to the unsigned test input. The deployer verifies the signature and checks its protected rollback state read-only. The VM verifies the signature independently and commits the accepted module version in its own rollback store. The test compares the admission store before and after launch and reads the VM version record. Signing keys stay outside the guest.

The current VM places ROSv2 imports in WSEA’s other-native-import category (mask 32). The test signer inspects the exact bytes before signing and accepts just `uwvm_ros_v2.abi () -> i32`. Deployment separately permits that one import. Application and VM signing policy files are independent of XML permission recommendations.

### Per-VM read-only clocks

A Preview 1 clock read requires two independent approvals in that VM's recommendation file. Expose the precise function imported by the binary and approve the required clock source. For example, a wasm32 program that reads monotonic time can request the following.

```xml
<recommendations>
  <interface name="wasip1.clock_time_get" expose="allow"/>
  <wasip1-clock name="monotonic-clock" access="allow"/>
</recommendations>
```

For target wasm64, use the SDK ABI spelling `wasip1.clock_time_get_wasm64`. Clock resolutions use `wasip1.clock_res_get` or `wasip1.clock_res_get_wasm64`. Read grants are `realtime-clock`, `monotonic-clock`, `process-clock`, `thread-clock` and the corresponding four `-resolution` names. The review editor uses keys such as `wasip1.clock.monotonic-clock`. An omitted interface is hidden. An explicitly denied interface links and returns a capability error. Each allowed interface still requires a grant for the selected source and operation. The deployer emits only per-VM options. Existing ROS interface recommendations retain their original names. A protected approval persists the exact decisions for cold restart. Clock approval does not grant timers, files or network access.

## Run the SDK, VM and deployer together

Use a C development installation with its site profile. This fixture compiles a guest against the installed headers, compares the SDK signatures with the deployment catalog, signs the guest using a disposable authority, and boots the selected engine inside a private x86_64 Linux guest. The serial log contains an individual decision for every ROS interface. Supply a fresh output directory and a separate private directory for the test authority. Signer keys stay on the host. Invoke the test inside the qualification cgroup.

```sh
/usr/bin/python3 tests/sdk_vm_deployment.py \
  --sdk "$INSTALLED_SDK" --vm "$VM" --vm-source "$VM_SOURCE" \
  --deployer "$DEPLOYER" --cosign "$COSIGN" --engine aot \
  --kernel "$KERNEL" --qemu "$QEMU" --bios "$BIOS" --firmware-directory "$FIRMWARE" \
  --output "$DEPLOYER_SOURCE/.tmp/site-aot" --authority-directory "$VM_SOURCE/.tmp/site-test-keys"
```

To exercise another installed SDK language, supply a compiled ABI-query application with `--sdk-abi-application FILE` and `--approved-build-receipt-sha256 DIGEST`. The latter pins the adjacent `FILE.wros-build.json` that the operator reviewed. This fixture accepts just the `uwvm_ros_v2.abi` import. It verifies the build for the selected VM, signs a private copy, then checks the deployer and VM signature decisions in the guest.

The full signed installation test accepts `--accelerator tcg` (default) or `--accelerator kvm` and an explicit `--guest-timeout-seconds 30..1800` (default 240). The cgroup must permit the selected backend. Two TCG runs used a public SDK installation for each language, the AOT engine, the fast-compile policy and a 1,200-second guest budget. The Lua interpreter built into Wasm passed all 42 checks in 499 seconds. The Fortran application passed the same 42 checks in 1,036 seconds. The guest starts fresh VM processes for grant, denial and signature verification. This time budget includes compilation and supervision across the entire test.

For D BetterC, the fixture checks the operator-approved receipt digest and runs the installed `wrd verify` against the selected VM before signing the application. A public Unitree D installation built the Xmake application at SDK commit `5fa860a356f19ed29aea514142eb897c3231951f`. It passed all 42 interpreter deployment cases under QEMU TCG, including the independent deployer and VM signature checks. The application imported only `uwvm_ros_v2.abi`.

### Local ROSv2 scheduling resources

A VM can use guards, clocks, timers and wait sets through ROSv2. Put each resource decision in that VM's separate recommendation file. The following example lets a guest open the alias `signal`, create a guard and trigger it. A call to the exposed `guard.take` returns permission denied.

```xml
<recommendations>
  <interface name="capability.open" expose="allow"/>
  <interface name="guard.create" expose="allow"/>
  <interface name="guard.trigger" expose="allow"/>
  <interface name="guard.take" expose="allow"/>
  <local-resource type="guard" alias="signal" operation="guard.create" access="allow"/>
  <local-resource type="guard" alias="signal" operation="guard.trigger" access="allow"/>
  <local-resource type="guard" alias="signal" operation="guard.take" access="deny"/>
</recommendations>
```

| Resource type | Type-specific operations |
| --- | --- |
| `guard` | `guard.create`, `guard.trigger`, `guard.take` |
| `clock.steady`, `clock.system` | `clock.create`, `clock.read` |
| `clock.ros` | `clock.create`, `clock.read`, `clock.update` |
| `timer` | `timer.create`, `timer.reset`, `timer.cancel`, `timer.take` |
| `wait` | `wait.create`, `wait.add`, `wait.remove`, `wait.acknowledge`, `wait.poll` |

Each type also accepts separate `resource.observe`, `resource.close` and `capability.revoke` decisions. Expose each import that the guest calls separately. The VM uses `resource.observe` when another operation refers to the resource. The VM checks the clock capability when creating a timer and the observed capability when attaching a resource to a wait set.

Use `allow local/guard/signal/guard.create` at the review prompt to add an operation. The deployer combines approved operations into one local grant per alias. An alias with zero approved operations stays unavailable. An alias has one type within its VM. On an authorized cold start, the deployer reads the reviewed operations from its protected state and the VM creates fresh handles. This path activates only ROSv2.

### Reviewing permission reports and metadata

The operator's risk report displays scores of 5/10 and above by default, with
unassessed items listed separately. Use `--risk-report 0` through
`--risk-report 10` to display scores at or above a different threshold. The
quoting form `--risk-report '>=7'` is also accepted. `--risk-report none`
turns off this report. The display threshold applies independently of the maximum score selected for adoption. Effective permissions, final launch confirmation
and required signature or policy diagnostics are still shown when applicable.

Each newly bound ROSv2 module can query the ABI major through `abi` by default (risk 0/10). This opens no data channel or resource. `deny abi` keeps the import linkable and returns permission denied. `hide abi` rejects the import at link time. The XML spelling for hiding is `<interface name="abi" expose="hidden"/>`. Use `remove abi` in the editor to restore the default. Cold recovery preserves explicit decisions from the approval.

A VM can read its own permission state through `permission.report` by
default. Limit the report by family or exact function. Use
`deny permission.report` to refuse calls while keeping the import linkable,
or `hide permission.report` to remove the import. In XML, set
`<interface name="permission.report" expose="hidden"/>` to recommend hiding.
Removing a whole-interface decision restores default read-only self
observation. Reading another module's declarations or VM runtime metadata
requires both the corresponding interface and a grant for the exact target.

```xml
<recommendations>
  <self-report selector="wasip1.fd_write" access="deny"/>
  <self-report selector="preloaddl" access="deny"/>
  <interface name="module.exports" expose="allow"/>
  <metadata type="module" alias="worker-view" target="worker" operation="module.exports" access="allow"/>
  <interface name="vm.describe" expose="allow"/>
  <metadata type="vm" alias="runtime-view" target="runtime" operation="vm.describe" access="allow"/>
</recommendations>
```

The VM also refuses a family-wide report that would reveal a denied function. An `allow` decision on a selector adds no filter of its own. Broader denials and the exposure of `permission.report` still apply. Filters can select `preloaddl`, `preloadwasm`, `wasip1`, `ros1v1`, `ros2v1` or `rosv2`. Queries can report that a configured target lacks compiled support.

For a module, each of `module.describe`, `module.imports`, `module.exports`, `module.importers`, `module.group` and `module.permission.report` needs its own review decision. A VM metadata grant accepts `vm.describe` on `runtime`. The guest supplies the approved alias to the observation operation. Each alias belongs to one type, target and binding in the process. These decisions convey read-only access to the corresponding metadata. Interactive review uses `report/SELECTOR` and `metadata/TYPE/ALIAS/TARGET/OPERATION`. Cold startup applies the saved decisions.

Before choosing a recovery module, inspect its MVP entry point, imports and resource ceilings. [Recovery module preflight](recovery-preflight.md)
