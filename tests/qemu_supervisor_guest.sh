#!/bin/sh
# Disposable guest only. The outer Python harness supplies a fresh initramfs and
# never attaches host disks, devices, a shared filesystem or a network interface.
set -eu
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup /scratch /state/admission /state/body
chmod 700 /scratch /state/admission /state/body
/bin/cosign wasm secure policy-init --output /trust/body.policy --state-dir /state/admission --trust-root /trust/root.pem --certificate /trust/signer.pem --module-id body --algorithms Ed25519
/bin/cosign wasm secure policy-init --output /trust/body-vm.policy --state-dir /state/body --trust-root /trust/root.pem --certificate /trust/signer.pem --module-id body --algorithms Ed25519
chmod 644 /trust/body.policy /trust/body-vm.policy
chown -R 10001:10001 /state/body
mount -t cgroup2 none /sys/fs/cgroup
echo '+cpu +memory +pids +cpuset' > /sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/delegated
echo 1073741824 > /sys/fs/cgroup/delegated/memory.max
echo 0 > /sys/fs/cgroup/delegated/memory.swap.max
echo 256 > /sys/fs/cgroup/delegated/pids.max
echo '+cpu +memory +pids +cpuset' > /sys/fs/cgroup/delegated/cgroup.subtree_control

fail() { echo "QEMU_SUPERVISOR_FAIL $*"; poweroff -f; exit 1; }
trap 'fail unexpected-command-failure' EXIT
pass() { echo "CASE $1 PASS"; }
base() {
    /bin/wros-deployer run /bundle/current.xml --policy-root /trust \
        --cosign /bin/cosign --scratch-directory /scratch \
        --cgroup-parent /sys/fs/cgroup/delegated --accept-recommendations "$@"
}
digest=$(sha256sum /bundle/unsigned.wasm); digest=${digest%% *}
configure() {
    name=$1; restart=$2; limit=$3; memory=$4
    printf '<deployment id="cell"><vm id="%s" module="unsigned.wasm" sha256="%s" policy="body.policy" memory-bytes="%s" pids="8" uid="10001" gid="10001" restart-on-crash="%s" restart-limit="%s" restart-delay-ms="100" %s/></deployment>\n' "$name" "$digest" "$memory" "$restart" "$limit" "${5:-}" > /bundle/current.xml
}
fixture() { base --runtime /bin/supervisor-peer --allow-unsigned "$1=$digest"; }
empty() { test ! -d /sys/fs/cgroup/delegated/wros-cell || fail stale-cgroup; }
not_running() {
    if test -f "/proc/$1/stat"; then
        state=$(cut -d ' ' -f3 "/proc/$1/stat")
        test "$state" = Z || fail "process-$1-still-running"
    fi
}
wait_started() {
    log=$1; expected=$2; loops=0
    while test "$(grep -c 'started with PID' "$log" || true)" -lt "$expected"; do
        loops=$((loops+1)); test "$loops" -lt 300 || { cat "$log"; fail start-timeout; }
        sleep .02
    done
}

configure normal false 0 134217728
fixture normal > /normal.log 2>&1 || { cat /normal.log; fail normal; }
grep -q 'PEER confined uid=10001 gid=10001 sealed=1' /normal.log || fail missing-confinement
empty; pass privileged-to-unprivileged-sealed-admission

configure placement false 0 134217728 'cpus="1" memory-nodes="1"'
fixture placement > /placement.log 2>&1 || { cat /placement.log; fail placement; }
grep -q 'PEER placement cpu=1 mems=1 page-node=1' /placement.log || fail placement-not-effective
empty; pass cpu-and-numa-placement-with-no-widening

configure placementcrash true 1 134217728 'cpus="1" memory-nodes="1"'
if fixture placementcrash > /placement-restart.log 2>&1; then fail placement-crash-status; fi
test "$(grep -c 'PEER placement cpu=1 mems=1 page-node=1' /placement-restart.log)" = 2 || { cat /placement-restart.log; fail placement-restart; }
empty; pass placement-preserved-across-cold-restart

configure normal false 0 134217728 'cpus="2"'
if fixture normal > /placement-cpu-deny.log 2>&1; then fail accepted-unavailable-cpu; fi
grep -q 'exceeds delegated effective CPU/NUMA sets' /placement-cpu-deny.log || fail wrong-cpu-rejection
empty; pass unavailable-cpu-rejected-before-spawn

configure normal false 0 134217728 'memory-nodes="2"'
if fixture normal > /placement-node-deny.log 2>&1; then fail accepted-unavailable-node; fi
grep -q 'exceeds delegated effective CPU/NUMA sets' /placement-node-deny.log || fail wrong-node-rejection
empty; pass unavailable-numa-node-rejected-before-spawn

echo 0 > /sys/fs/cgroup/delegated/cpuset.cpus
configure normal false 0 134217728 'cpus="1"'
if fixture normal > /placement-parent-deny.log 2>&1; then fail expanded-parent-placement; fi
grep -q 'exceeds delegated effective CPU/NUMA sets' /placement-parent-deny.log || fail wrong-parent-rejection
echo 0-1 > /sys/fs/cgroup/delegated/cpuset.cpus
empty; pass delegated-cpu-boundary-cannot-expand

echo -cpuset > /sys/fs/cgroup/delegated/cgroup.subtree_control
if fixture normal > /placement-controller-deny.log 2>&1; then fail ignored-missing-cpuset; fi
grep -q 'requires an enabled cpuset controller' /placement-controller-deny.log || fail wrong-controller-rejection
echo +cpuset > /sys/fs/cgroup/delegated/cgroup.subtree_control
empty; pass missing-cpuset-controller-fails-closed

configure crash false 3 134217728
if fixture crash > /crash.log 2>&1; then fail unapproved-restart; fi
test "$(grep -c 'started with PID' /crash.log)" = 1 || fail unapproved-generation
empty; pass no-implicit-crash-restart

configure crash true 2 134217728
if fixture crash > /restart.log 2>&1; then fail unbounded-restart; fi
test "$(grep -c 'started with PID' /restart.log)" = 3 || { cat /restart.log; fail restart-budget; }
empty; pass authorized-restart-budget

configure orphan false 0 134217728
fixture orphan > /orphan.log 2>&1 || { cat /orphan.log; fail orphan; }
empty; pass reparented-descendant-cleanup

configure pids false 0 134217728
fixture pids > /pids.log 2>&1 || { cat /pids.log; fail pids; }
grep -q 'task limit after' /pids.log || fail task-limit-not-hit
empty; pass kernel-task-limit

configure memory false 0 33554432
if fixture memory > /memory.log 2>&1; then fail memory-limit-not-hit; fi
grep -Eq 'oom_kill [1-9]' /memory.log || { cat /memory.log; fail missing-oom-evidence; }
empty; pass kernel-memory-oom-containment

configure stop true 2 134217728
fixture stop > /stop.log 2>&1 & management=$!
# Kill the actual deployer (the function may run in a shell subprocess).
wait_started /stop.log 1
manager=$(cat /proc/$management/task/$management/children | awk '{print $1}')
test -n "$manager" || manager=$management
kill -TERM "$manager"
wait "$management" || { cat /stop.log; fail manual-stop; }
test "$(grep -c 'started with PID' /stop.log)" = 1 || fail restart-after-stop
empty; pass operator-stop-overrides-recovery

configure flood false 0 134217728
fixture flood > /flood.log 2>&1 || { tail -10 /flood.log; fail output-flood; }
test "$(wc -c < /flood.log)" -lt 20000 || fail unbounded-diagnostic
empty; pass bounded-diagnostic-flood

configure floodstop false 0 134217728
/bin/supervisor-peer --blocked-supervisor /bin/wros-deployer run /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --accept-recommendations --runtime /bin/supervisor-peer --allow-unsigned "floodstop=$digest" > /backpressure.log 2>&1 || { cat /backpressure.log; fail blocked-audit; }
empty; pass blocked-audit-consumer-cannot-block-stop

# Use the real VM and a real WSEA signature with two independently owned stores.
signed=$(sha256sum /bundle/body.wasm); signed=${signed%% *}
printf '<deployment id="cell"><vm id="body" module="body.wasm" sha256="%s" policy="body.policy" vm-policy="body-vm.policy" memory-bytes="268435456" pids="16" uid="10001" gid="10001"/></deployment>\n' "$signed" > /bundle/current.xml
base --runtime /bin/uwvm2-ros > /signed.log 2>&1 || {
    cat /signed.log
    /bin/strace -f -o /failure.trace /bin/wros-deployer run /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --accept-recommendations --runtime /bin/uwvm2-ros || true
    tail -100 /failure.trace
    fail signed-real-vm
}
grep -q 'WSEA policy and signature verified' /signed.log || fail absent-primary-verification
grep -q -- '--secure' /signed.log || fail absent-secondary-verification
empty; pass actual-vm-double-verification

loopdigest=$(sha256sum /bundle/loop.wasm); loopdigest=${loopdigest%% *}
printf '<deployment id="cell"><vm id="one" module="loop.wasm" sha256="%s" policy="body.policy" memory-bytes="268435456" pids="16" uid="10001" gid="10001" cpus="0" memory-nodes="0"/><vm id="two" module="loop.wasm" sha256="%s" policy="body.policy" memory-bytes="268435456" pids="16" uid="10002" gid="10002" cpus="1" memory-nodes="1"/></deployment>\n' "$loopdigest" "$loopdigest" > /bundle/current.xml
base --runtime /bin/uwvm2-ros --allow-unsigned "one=$loopdigest" --allow-unsigned "two=$loopdigest" > /multiple.log 2>&1 & management=$!
wait_started /multiple.log 2
test -n "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-one/cgroup.procs)" || fail missing-first-group
test -n "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-two/cgroup.procs)" || fail missing-second-group
first=$(cat /sys/fs/cgroup/delegated/wros-cell/vm-one/cgroup.procs)
second=$(cat /sys/fs/cgroup/delegated/wros-cell/vm-two/cgroup.procs)
test "$first" != "$second" || fail shared-pid
test "$(awk '/Cpus_allowed_list:/{print $2}' /proc/$first/status)" = 0 || fail first-cpu
test "$(awk '/Mems_allowed_list:/{print $2}' /proc/$first/status)" = 0 || fail first-numa
test "$(awk '/Cpus_allowed_list:/{print $2}' /proc/$second/status)" = 1 || fail second-cpu
test "$(awk '/Mems_allowed_list:/{print $2}' /proc/$second/status)" = 1 || fail second-numa
manager=$(cat /proc/$management/task/$management/children | awk '{print $1}')
test -n "$manager" || manager=$management
kill -TERM "$manager"; wait "$management" || { cat /multiple.log; fail multi-stop; }
not_running "$first"; not_running "$second"; empty; pass actual-two-vm-independent-cgroups

sdkdigest=$(sha256sum /bundle/sdk.wasm); sdkdigest=${sdkdigest%% *}
printf '<deployment id="cell"><vm id="sdk" module="sdk.wasm" sha256="%s" policy="body.policy" recommendations="permissions.xml" memory-bytes="268435456" pids="16" uid="10001" gid="10001"/></deployment>\n' "$sdkdigest" > /bundle/current.xml
printf '<recommendations><interface name="abi" expose="allow"/></recommendations>\n' > /bundle/permissions.xml
base --runtime /bin/uwvm2-ros --allow-unsigned "sdk=$sdkdigest" > /sdk-allow.log 2>&1 || { cat /sdk-allow.log; fail sdk-allowed; }
empty; pass sdk-compiled-ros-interface-allowed
printf '<recommendations><interface name="abi" expose="deny"/></recommendations>\n' > /bundle/permissions.xml
if base --runtime /bin/uwvm2-ros --allow-unsigned "sdk=$sdkdigest" > /sdk-deny.log 2>&1; then fail sdk-denied; fi
empty; pass sdk-compiled-ros-interface-denied

configure parentdeath true 2 134217728
fixture parentdeath > /death.log 2>&1 & management=$!
wait_started /death.log 1
worker=$(cat /sys/fs/cgroup/delegated/wros-cell/vm-parentdeath/cgroup.procs)
manager=$(cat /proc/$management/task/$management/children | awk '{print $1}')
test -n "$manager" || manager=$management
kill -KILL "$manager"; wait "$management" || true
sleep .1; not_running "$worker"
if fixture parentdeath > /stale.log 2>&1; then fail reused-stale-deployment; fi
# Simulate the ultimate service supervisor reclaiming the dead manager's tree.
echo 1 > /sys/fs/cgroup/delegated/wros-cell/cgroup.kill
rmdir /sys/fs/cgroup/delegated/wros-cell/vm-parentdeath
rmdir /sys/fs/cgroup/delegated/wros-cell
pass manager-death-fences-child-and-stale-tree

for log in /normal.log /placement*.log /crash.log /restart.log /orphan.log /pids.log /memory.log /stop.log /flood.log /backpressure.log /signed.log /multiple.log /sdk-allow.log /sdk-deny.log /death.log /stale.log; do
    echo "AUDIT_LOG $log"; cat "$log"
done

echo QEMU_SUPERVISOR_PASS
trap - EXIT
poweroff -f
