# Device ownership and kernel access control

Every deployed VM requires a Linux cgroup v2 device BPF policy before it starts.
Missing support, verifier failure, incompatible ancestor policy or failed
attachment rejects execution. There is no unrestricted fallback. This authority
belongs to the external supervisor; the VM gains no BPF, cgroup or process
creation API.

The fixed VM runtime baseline allows character device 1:3 (`/dev/null`) for
read/write and 1:5, 1:8, 1:9 (`zero`, `random`, `urandom`) for read only. All
other device opens and all `mknod` operations are denied. Review and execution
print this as INFO. This grants no Wasm import or WASIp1 path; separate reviewed
interface and resource permissions still apply. Physical devices belong in
isolated external providers.

## Inspect without opening hardware

`devices::Device::inspect` walks an exact absolute `/dev` path with pinned
`O_PATH` descriptors. It does not open the device for reading or writing.
Ancestors must be root-owned and not group/other writable. Symlinks, empty/dot/
parent components, non-device files, unlinked nodes and excessive length/depth
fail. The final inode must be root-owned. A trusted platform provisioner resolves
by-id aliases before supplying the canonical node.

The key is character/block type, major number and minor number. Different nodes
for the same kernel device have the same key. `revalidate` rejects a replaced
inode even with an unchanged number. Hotplug can reuse numbers without replacing
the node, so this does not prove a physical serial number, bus identity or safe
firmware state. The platform must independently confirm approved hardware and
safe state. Network-controlled robots need a separate ownership/network policy.

## Preserve the original owner

`ownership::claim_with_devices` reserves final UID/GID identities and device
keys in one transaction in root-only `/run/wros-ownership`. A request permits
at most 256 UID/GID and 128 device records. Duplicate keys, including aliases in
one request, fail. Ownership binds the exact canonical cgroup parent and
deployment name. A second manager cannot take a device after the original
manager exits or crashes. New clients must use the original deployment.
Normal shutdown does not remove records.

`Reservations::check_devices` checks the manager process incarnation, owner,
requested keys and pinned nodes. A forked handle is not provisioning authority.
The original manager must still satisfy approval, safe-state, old-process
draining and recovery requirements. Ownership does not grant motion. `/run`
normally clears at boot; reacquisition does not restore motion permission.

All managers must share the protected host registry and device-number namespace.
A private container registry cannot coordinate the same physical device.
Advisory records cannot constrain unmanaged privileged processes. Kernel access
control is a separate layer. Root, kernel integrity, hardware mapping and the
trusted command receiver remain assumptions.

## Fixed kernel policy

`devices::Policy` accepts zero to 128 exact read, write or read/write rules.
Duplicate keys fail rather than implicitly combine authority. There are no
wildcards, mknod grants, raw bytecode, maps or helpers. The generated program
has at most 1,033 instructions and only forward branches. Linux verifies it
before admission. UAPI structures have explicit padding/alignment for all five
userspace ABIs.

`attach_empty` requires a protected empty cgroup v2 domain under exclusive
provisioning ownership. It refuses existing programs and never replaces them or
uses `ALLOW_OVERRIDE`. Ancestor restrictions cannot be widened. Concurrent root
administration of the same group is outside the contract. Closing the program
FD deliberately does not detach its policy; it remains until the drained group
is removed. Manager death cannot silently broaden surviving processes' rights.

The kernel [device controller](https://docs.kernel.org/admin-guide/cgroup-v2.html#device-controller)
checks device opens and node creation. It does **not** revoke already-open FDs,
filter individual ioctls, validate vendor protocols or prove safe physical stop.
Launch code must close unapproved inherited descriptors; bootstrap must reject
unexpected FD transfer. Device handles must never enter a VM from a provider.
Command permission and arbitration belong in a trusted receiver outside vendor
code. Motion still requires independent safety and human confirmation.

## Tests and integration limits

`tests/qemu_devices.py` runs 21 kernel cases using Linux pseudo devices in an
offline 2 GiB guest, inside the existing 64 GiB test group. It covers default
denial, independent read/write rights, maximum rules, ancestors/siblings,
existing-policy protection, lifetime after FD close, invalid/populated targets,
aliases, inode replacement, manager death, retained ownership, damaged records
and FD cleanup. One case deliberately demonstrates the already-open-FD boundary.
No host mknod, BPF installation, privileged command, disk, shared folder, network
or physical device is used.

The separate 37-case supervisor suite checks this policy in an unprivileged
native fixture alongside actual signed VMs, isolated cgroups, placement,
resource exhaustion and recovery. Five-ABI userspace tests check bytecode,
layouts and ownership; QEMU-user's user-owned redirected root is correctly
rejected. Positive device inspection and BPF enforcement require the full-kernel
fixture. QEMU timings are not native hardware performance measurements.

The VM baseline is active in production supervision. Native provider declarations
remain refused by `run`/`resume`: reviewed resource XML, vendor adapters, physical
identity, safe stop and native lifecycle admission still require integration.
These primitives and the [encrypted handoff](attachment-provisioning.md) do not
qualify arbitrary vendor drivers or establish industrial safety certification.
