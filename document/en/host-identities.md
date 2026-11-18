# Host identity ownership

Separate cgroups and namespaces do not make reuse of a Linux UID or GID safe.
Credentials still affect signals, procfs and filesystem access. Before creating
any workload, `run` and `resume` now reserve every final UID and GID in the shared
host registry `/run/wros-ownership`. The supervisor API enforces the same check.
`plan`, `review`, `verify`, `authorize` and `service` do not acquire identities.

The deployer creates the registry with mode 0700 beneath a root-owned `/run`.
Records and the admission lock have mode 0600. Symlinks, non-regular files,
multiple hard links, unexpected ownership or permissions, and malformed records
cause rejection. A batch contains at most 256 distinct UID/GID records. Names
are canonical nonzero decimal identities, excluding the invalid all-ones value.

An owner is bound to the exact canonical workload cgroup parent and deployment
name. All existing records must match before any new claim is written. A short
global admission lock serializes publication; a deployment lock and individual nonblocking identity locks remain
held through old-group cleanup, approval consumption, supervision and shutdown.
A stale second approval cannot reclaim a live manager's group before its
identity conflict is checked. The deployment lock also rejects a stale
configuration with different identities that targets the same cgroup tree.
A conflicting manager fails before it creates a
workload and does not signal the existing owner. Managers with disjoint
identities may run concurrently. Registry descriptors close on workload exec and
are never exposed through guest imports or local provider channels.

Closing a manager's descriptors does not erase its owner records. After SIGKILL,
an unrelated manager still cannot adopt the identities merely because their
locks are available. The original deployment can reacquire them, but must also
satisfy its separate approval, cgroup cleanup and restart checks. Normal shutdown
also preserves ownership. Additional clients must go through the original
deployment rather than transferring ownership between deployers.

Records are synchronized before launch and include their owner, identity and
checksum. The checksum detects corruption; it is not an authorization signature.
A failed write may leave conservative partial reservations. An incomplete record
blocks execution and is never inferred to be an unused identity. The deployer
does not automatically delete or repair such records. An administrator must
establish that all affected processes have stopped before offline repair.

`/run` is normally cleared at machine boot. A platform that preserves it retains
the reservations as well; this release does not automatically expire them.
All managers sharing host identities must see the same registry and consistent
host UID/GID and cgroup naming. Do not place a separate registry in each
container's private `/run`. The platform must reserve these OS identities for
WROS: this coordination cannot stop an unmanaged process or a privileged
administrator from using the same credentials. It is not a device-access filter,
physical hardware lease, cross-host ownership service or motion authorization.
Native driver provisioning remains disabled pending those separate controls.

The registry is consulted during admission, not during ROS/DDS or driver calls.
Its filesystem latency must not be included as a per-message transport cost.
Tests cover concurrent conflicts on UID and GID independently, disjoint managers,
manager death, stale competing approvals, original-owner recovery, damaged records, links, private access
and descriptor inheritance. Full-kernel cases run in the disposable QEMU fixture;
they do not establish physical safety certification.
