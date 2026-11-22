# Independent service supervision

Managers sharing a host must also share the [host identity registry](host-identities.md).
It excludes conflicting UID/GID use and competing managers of the same deployment
before old-group cleanup. Namespace or cgroup separation alone does not establish
exclusive host identity ownership.

`wros-deployer service` renders a systemd unit. It does not install, enable or start a host service. `authorize` performs signature admission and operator permission review, then saves a one-use initial activation in a private durable state directory. `resume` consumes that activation before creating a VM. Later automatic starts require the separate XML crash or boot grants.

This implementation requires Linux cgroup v2. The generated unit requires systemd 254 or later because it uses `DelegateSubgroup=manager`. It has been exercised with systemd 257 under a disposable x86_64 Linux kernel. The Rust interfaces also execute on the five supported userspace ABIs; this does not qualify the service manager and kernel of every target platform.

## Resource and lifecycle ownership

The independent service manager owns the root and all descendant processes:

```text
/sys/fs/cgroup/system.slice/wros-cell.service
  manager                       deployer, admission verifier, audit thread
  workloads
    wros-cell
      vm-body                   one VM and all its descendants
  .control                      reserved for the independent service manager
```

The deployer checks its current kernel membership before any verifier or VM starts. It refuses an unrelated cgroup, a missing controller, a populated root, an unexpected child, insufficient outer limits or a different existing workload budget. It only configures children of the exact delegated root. It never moves itself to another cgroup, changes an ancestor or delegates cgroup handles to a guest.

After creating the reviewed namespaces and dropping credentials, the deployer
installs an irreversible seccomp filter before executing the VM. `setns`,
`unshare` and namespace-creating legacy `clone` calls return `EPERM`.
`clone3` returns `ENOSYS` so libraries can use ordinary legacy thread creation;
a library that requires `clone3` without a fallback is incompatible with this
policy. Ordinary threads and child processes remain subject to the task budget.
Unexpected syscall ABIs are killed. There is no switch that silently disables
this policy when seccomp is missing. The policy pins established namespace
membership; it is not a complete syscall or filesystem sandbox.

This boundary is necessary when a provisioner attests the clock domain of a
local encrypted attachment. A cgroup does not prevent time-namespace changes.
The VM accepts only kernel namespace evidence plus the existing exact peer
credentials, process-lifetime pin and mutual TLS binding. The test-only
`tests/qemu_driver_identity.py` exercises these checks under different non-root
identities. Native driver orchestration is still refused by the production
deployment command until its remaining lifecycle and ownership requirements
are implemented and qualified.

The XML must explicitly budget the manager:

```xml
<deployment id="cell">
  <supervisor memory-bytes="536870912" pids="128" cpu-micros="100000"
              cpus="0" memory-nodes="0"/>
  <vm id="body" module="body.wasm" sha256="REPLACE_WITH_64_LOWERCASE_HEX"
      policy="body.policy" vm-policy="body-vm.policy"
      uid="10001" gid="10001" memory-bytes="268435456" pids="16"
      cpu-micros="100000" cpus="1" memory-nodes="0"
      start-on-boot="false" restart-on-crash="false"
      restart-limit="3" restart-delay-ms="1000"/>
</deployment>
```

Manager memory must be at least 16 MiB, its task limit from 8 to 65536, and its CPU quota from 1000 to 100000000 microseconds per 100000-microsecond period. Those are validation bounds, not sizing recommendations. Allow sufficient memory and tasks for the selected verifier, module snapshots, runtime metadata and diagnostics. Optional CPU and NUMA sets must be available in full; otherwise startup fails.

The generated service memory limit is the sum of all VM limits, the manager limit and 4 MiB of bounded control headroom. Its task limit adds four control tasks to the manager and VM limits. Swap is disabled. The manager and every VM have separate group-OOM handling. A workload cannot consume the manager's configured child-group allowance. Ancestor pressure, scheduling, memory hotplug and uninterruptible kernel tasks can still prevent progress. These settings neither reserve physical cores nor implement an independent hardware stop.

`KillMode=mixed` gives the deployer SIGTERM first so it can persist stop intent, then allows systemd to kill the entire remaining tree. The stop deadline is five seconds. A killed manager does not leave TERM-ignoring orphan processes alive across the next activation. `Restart=on-failure` recovers abnormal manager exits and panics; exit code 1 denotes a reported admission, configuration or supervision failure and is excluded from automatic restart. Systemd also limits starts to three in sixty seconds. These outer limits cannot increase the durable per-VM retry grant.

## Review, render and start

Install protected runtime, verifier and deployer binaries separately from the submitted bundle. Prepare the private state and staging directories according to the [main guide](README.md). The state directory must already exist with root ownership and mode 0700. The future service cgroup need not exist during authorization.

```sh
/opt/wros/bin/wros-deployer authorize /protected/bundles/cell/deployment.xml \
  --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --state-directory /protected/state/cell \
  --supervisor-cgroup /sys/fs/cgroup/system.slice/wros-cell.service
```

Review and approval require a terminal. Confirm each VM in the editor or use `--accept-recommendations` to adopt all parsed recommendations in one step. The effective decisions and independent risk report remain visible according to `--risk-report`. In either mode, type `authorize DEPLOYMENT_ID` to persist the reviewed authorization. Signature exceptions, if required, are individually bound to the VM and exact module digest. `authorize` refuses a populated service root or a concurrently owned state directory. It does not stop an existing deployment to replace its approval.

After review, render the unit with the same paths:

```sh
/opt/wros/bin/wros-deployer service /protected/bundles/cell/deployment.xml \
  --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --state-directory /protected/state/cell \
  --supervisor-cgroup /sys/fs/cgroup/system.slice/wros-cell.service \
  > wros-cell.service
```

An administrator reviews and installs that file as `wros-cell.service`, reloads systemd and starts it. Enabling the service for boot does not grant VM startup: `start-on-boot` in the reviewed XML still controls that behavior. The unit uses complete CLI option names and no shell. Argument escaping preserves spaces, dollar signs and literal systemd percent specifiers. A modified manifest, executable, trust policy, state location or cgroup path invalidates the saved binding and requires fresh review.

The initial activation is valid once in the same kernel boot. It does not consume a crash retry and it cannot survive a manager failure during activation as an unlimited retry. On a later machine boot, only the explicit boot grant permits startup. An ordinary manual service stop persists stopped intent. If termination is forced before durable storage can acknowledge the stop, persisted state may still describe an interrupted generation; the outer service manager must keep it stopped until an operator resolves that uncertainty. A boot grant intentionally permits a new cold start after a later boot, even after a previous-boot stop. No path restores actuator state or motion authority.

Do not use `--cgroup-parent` together with `--supervisor-cgroup`. The former remains available for a manually supervised external workload subtree; it does not apply a manager budget. Specifying a supervisor XML budget without the managed mode is rejected rather than silently ignored.

## Inspect the recovery record

```sh
wros-deployer status --state-directory /protected/state/cell
```

Run the command as the owner of the private state directory. It reads one
checksummed approval record while the manager can continue running. It shows
whether the record is from the current boot and prints each VM's recorded
phase, generation and consumed retry count. It acquires no supervisor lock
and grants no control authority. If a concurrent replacement removes the
file before its ownership check completes, repeat the observation. Use the
independent manager to check live process state.

## Platforms without this systemd capability

The production `--supervisor-cgroup` contract is independent of systemd. An alternative platform supervisor must create an exclusive bounded root, enable delegation from its ancestors, place the deployer alone in the `manager` child, own every descendant's lifecycle, provide bounded restart and whole-tree shutdown, and invoke the exact approved `resume` command. The deployer validates the observable cgroup contract. It cannot prove that an arbitrary external supervisor will recover after its own failure.

A test shell supervisor exercises the same boundary in QEMU. It is not a shipped industrial service manager. Platforms lacking the required kernel controls or independent lifecycle supervision fail closed; no weaker fallback is automatically selected. A platform-specific implementation needs its own kernel, failure and shutdown qualification before deployment.

## Qualification and remaining work

`tests/qemu_service.py` boots real systemd and the real deployer, with both a hostile native test peer and the actual VM. Cases include absent approval, exact argument preservation, separate CPU/NUMA/memory/task limits, foreign membership rejection, single-use initial authorization, manager SIGKILL, TERM-ignoring descendants, persistent retry limits, manual stop, insufficient delegation, unknown subgroups, manager group-OOM and the alternative-supervisor layout. The guest has no network, shared host filesystem or physical device; its process remains inside the existing 64 GiB host test cgroup.

This service integration does not implement the strict-MVP recovery watchdog, native provider provisioning, live updates or complete device safety supervision. Physical safe-state confirmation and fresh operator confirmation remain necessary before motion. Fault injection and cross-ABI execution provide bounded evidence, not industrial safety certification.

The service semantics follow the official [resource delegation](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html), [process termination](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html) and [restart configuration](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) documentation.

The supervisor keeps up to 8,192 bytes of combined stdout and stderr per VM generation. Each diagnostic includes the VM identity, generation and stream. When a read first exceeds that budget, the supervisor emits one warning and continues draining both pipes. Completeness of a VM audit cannot be inferred from a truncated diagnostic stream.
