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

printf '<deployment id="independent"><vm id="stop-independent" module="unsigned.wasm" sha256="%s" policy="body.policy" memory-bytes="134217728" pids="8" uid="10100" gid="10100"/></deployment>\n' "$digest" > /bundle/independent.xml
/bin/wros-deployer run /bundle/independent.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --accept-recommendations --runtime /bin/supervisor-peer --allow-unsigned "stop-independent=$digest" > /independent.log 2>&1 & independent=$!
wait_started /independent.log 1
loops=0
while ! grep -q 'PEER orphan pid=' /independent.log; do
    loops=$((loops+1)); test "$loops" -lt 300 || { cat /independent.log; fail independent-descendant; }
    sleep .02
done
independent_group=/sys/fs/cgroup/delegated/wros-independent/vm-stop-independent
independent_pids=$(cat "$independent_group/cgroup.procs")
test "$(echo "$independent_pids" | wc -l)" = 2 || fail independent-members
{
    printf '<deployment id="cell">\n'
    for index in 1 2 3; do
        printf '<vm id="stop-%s" module="unsigned.wasm" sha256="%s" policy="body.policy" memory-bytes="134217728" pids="8" uid="%s" gid="%s"/>\n' "$index" "$digest" "$((10100+index))" "$((10100+index))"
    done
    printf '</deployment>\n'
} > /bundle/current.xml
/bin/strace -f -yy -e trace=write,pidfd_send_signal -o /tree-stop.trace \
    /bin/wros-deployer run /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --accept-recommendations --runtime /bin/supervisor-peer --allow-unsigned "stop-1=$digest" --allow-unsigned "stop-2=$digest" --allow-unsigned "stop-3=$digest" > /tree-stop.log 2>&1 & trace=$!
wait_started /tree-stop.log 3
loops=0
while test "$(grep -c 'PEER orphan pid=' /tree-stop.log || true)" -lt 3; do
    loops=$((loops+1)); test "$loops" -lt 300 || { cat /tree-stop.log; fail tree-stop-descendants; }
    sleep .02
done
manager=$(cat /proc/$trace/task/$trace/children | awk '{print $1}')
test -n "$manager" || fail tree-stop-deployer
pids=
for index in 1 2 3; do
    members=$(cat "/sys/fs/cgroup/delegated/wros-cell/vm-stop-$index/cgroup.procs")
    test "$(echo "$members" | wc -l)" = 2 || fail tree-stop-members
    pids="$pids $members"
done
before=$(cut -d ' ' -f1 /proc/uptime)
kill -TERM "$manager"
wait "$trace" || { cat /tree-stop.log; fail tree-stop; }
after=$(cut -d ' ' -f1 /proc/uptime)
awk -v before="$before" -v after="$after" 'BEGIN {printf "MEASURE tree-stop-ms %.0f\n", (after-before)*1000; exit (after < before || after-before > 5)}' || fail tree-stop-time
awk '/pidfd_send_signal.*SIGTERM/ {term++}
     term && /cgroup.kill>/ && !forced {forced=1; root=$0 ~ /\/wros-cell\/cgroup.kill>.* = 1$/}
     END {exit !(term == 3 && forced && root)}' /tree-stop.trace || { grep -E 'pidfd_send_signal|cgroup.kill' /tree-stop.trace; fail tree-stop-first-force-scope; }
for pid in $pids; do not_running "$pid"; done
for pid in $independent_pids; do
    grep -qx "$pid" "$independent_group/cgroup.procs" || fail tree-stop-affected-independent
done
kill -TERM "$independent"
wait "$independent" || { cat /independent.log; fail independent-stop; }
empty
test ! -d /sys/fs/cgroup/delegated/wros-independent || fail independent-stale-cgroup
pass operator-stop-forces-whole-tree-and-preserves-independent-deployment

configure flood false 0 134217728
fixture flood > /flood.log 2>&1 || { tail -10 /flood.log; fail output-flood; }
test "$(wc -c < /flood.log)" -lt 20000 || fail unbounded-diagnostic
test "$(grep -c 'WARNING VM "flood" generation 1 diagnostic byte limit reached' /flood.log)" = 1 || fail diagnostic-loss-marker
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
# Another manager must not acquire either identity independently, and its
# rejection must leave the two existing VMs running. Resource names are host
# identities; matching only a GID is also an isolation failure.
competitor() {
    printf '<deployment id="other"><vm id="normal" module="unsigned.wasm" sha256="%s" policy="body.policy" memory-bytes="134217728" pids="8" uid="%s" gid="%s"/></deployment>\n' "$digest" "$1" "$2" > /bundle/other.xml
    /bin/wros-deployer run /bundle/other.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --runtime /bin/supervisor-peer --accept-recommendations --allow-unsigned "normal=$digest"
}
if competitor 10001 11001 > /uid-conflict.log 2>&1; then fail uid-collision-accepted; fi
grep -q 'host identity or device is busy' /uid-conflict.log || { cat /uid-conflict.log; fail wrong-uid-conflict; }
test ! -d /sys/fs/cgroup/delegated/wros-other || fail competing-cgroup-created
test "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-one/cgroup.procs)" = "$first" || fail original-vm-disturbed
pass cross-deployer-uid-collision-preserves-original
if competitor 11002 10001 > /gid-conflict.log 2>&1; then fail gid-collision-accepted; fi
grep -q 'host identity or device is busy' /gid-conflict.log || { cat /gid-conflict.log; fail wrong-gid-conflict; }
pass cross-deployer-gid-collision-denied
competitor 11003 11003 > /uid-distinct.log 2>&1 || { cat /uid-distinct.log; fail separate-deployment-denied; }
grep -q 'PEER confined uid=11003 gid=11003' /uid-distinct.log || fail distinct-deployment-not-executed
test "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-one/cgroup.procs)" = "$first" || fail disjoint-deployment-disturbed-original
pass disjoint-deployer-identities-can-execute-concurrently
manager=$(cat /proc/$management/task/$management/children | awk '{print $1}')
test -n "$manager" || manager=$management
kill -TERM "$manager"; wait "$management" || { cat /multiple.log; fail multi-stop; }
not_running "$first"; not_running "$second"; empty; pass actual-two-vm-independent-cgroups
if competitor 10001 11001 > /uid-stale.log 2>&1; then fail implicit-identity-handoff; fi
grep -q 'belongs to another deployment or has an invalid record' /uid-stale.log || { cat /uid-stale.log; fail lost-owner-record; }
pass exited-deployer-does-not-transfer-identity

sdkdigest=$(sha256sum /bundle/sdk.wasm); sdkdigest=${sdkdigest%% *}
sdk_memory=$(cat /bundle/sdk-memory-bytes)
sdk_engine=$(cat /bundle/sdk-engine)
sdk_aot_attribute=
if test -f /bundle/sdk-aot-policy; then
    sdk_aot_policy=$(cat /bundle/sdk-aot-policy)
    case "$sdk_aot_policy" in default|fast-compile|balanced|max) ;; *) fail invalid-aot-policy ;; esac
    sdk_aot_attribute=" aot-policy=\"$sdk_aot_policy\""
fi
parent_limit=$(cat /sys/fs/cgroup/delegated/memory.max)
if [ "$sdk_memory" -gt "$parent_limit" ]; then
    echo "$sdk_memory" > /sys/fs/cgroup/delegated/memory.max || fail sdk-parent-budget
fi
select_sdk() {
    printf '<deployment id="cell"><vm id="sdk" module="%s" sha256="%s" policy="body.policy" recommendations="permissions.xml" memory-bytes="%s" engine="%s"%s pids="16" uid="10001" gid="10001"/></deployment>\n' "$1" "$2" "$sdk_memory" "$sdk_engine" "$sdk_aot_attribute" > /bundle/current.xml
}
sdk_rights() {
    if test -f /bundle/reviewed-interfaces.xml; then
        cp /bundle/reviewed-interfaces.xml /bundle/permissions.xml
    else
        printf '<recommendations><interface name="abi" expose="allow"/></recommendations>\n' > /bundle/permissions.xml
    fi
}
select_sdk sdk.wasm "$sdkdigest"
sdk_rights
base --runtime /bin/uwvm2-ros --allow-unsigned "sdk=$sdkdigest" > /sdk-allow.log 2>&1 || { cat /sdk-allow.log; fail sdk-allowed; }
if test -n "$sdk_aot_attribute"; then
    grep -Fq "\"--runtime-llvm-jit-policy\", \"$sdk_aot_policy\"" /sdk-allow.log || fail aot-policy-argument
fi
empty; pass sdk-compiled-ros-interface-allowed
if test -f /bundle/reviewed-interfaces.xml; then
    awk '{gsub(/expose="allow"/, "expose=\"deny\""); print}' /bundle/reviewed-interfaces.xml > /bundle/permissions.xml
else
    printf '<recommendations><interface name="abi" expose="deny"/></recommendations>\n' > /bundle/permissions.xml
fi
if base --runtime /bin/uwvm2-ros --allow-unsigned "sdk=$sdkdigest" > /sdk-deny.log 2>&1; then fail sdk-denied; fi
grep -q 'INFO VM "sdk" resource events memory: .*oom_kill 0' /sdk-deny.log || { cat /sdk-deny.log; fail sdk-denial-resource-failure; }
empty; pass sdk-compiled-ros-interface-denied

probedigest=$(sha256sum /bundle/abi-denied.wasm); probedigest=${probedigest%% *}
select_sdk abi-denied.wasm "$probedigest"
base --runtime /bin/uwvm2-ros --allow-unsigned "sdk=$probedigest" > /sdk-status.log 2>&1 || { cat /sdk-status.log; fail wrong-denied-abi-status; }
empty; pass explicit-abi-denial-returns-permission-code

select_sdk sdk.wasm "$sdkdigest"
printf '<recommendations/>\n' > /bundle/permissions.xml
if base --runtime /bin/uwvm2-ros --allow-unsigned "sdk=$sdkdigest" > /sdk-hidden.log 2>&1; then fail sdk-hidden; fi
grep -Fq 'ROS scene interface is hidden' /sdk-hidden.log || { cat /sdk-hidden.log; fail wrong-sdk-hidden-diagnostic; }
empty; pass sdk-hidden-import-rejected-before-entry

if test -f /bundle/sdk.signed.wasm; then
    mkdir /state/sdk-admission /state/sdk-vm
    chmod 700 /state/sdk-admission /state/sdk-vm
    for role in admission vm; do
        /bin/cosign wasm secure policy-init --output "/trust/sdk-$role.policy" --state-dir "/state/sdk-$role" --trust-root /trust/root.pem --certificate /trust/signer.pem --module-id sdk --algorithms Ed25519 --capabilities 32
        chmod 644 "/trust/sdk-$role.policy"
        if grep -Fq 'sdk|1|' "/state/sdk-$role/state"; then fail preexisting-sdk-verification; fi
    done
    admission_state_before=$(sha256sum /state/sdk-admission/state)
    chown -R 10001:10001 /state/sdk-vm
    signed_sdk=$(sha256sum /bundle/sdk.signed.wasm); signed_sdk=${signed_sdk%% *}
    printf '<deployment id="cell"><vm id="sdk" module="sdk.signed.wasm" sha256="%s" policy="sdk-admission.policy" vm-policy="sdk-vm.policy" recommendations="permissions.xml" memory-bytes="%s" engine="%s"%s pids="16" uid="10001" gid="10001"/></deployment>\n' "$signed_sdk" "$sdk_memory" "$sdk_engine" "$sdk_aot_attribute" > /bundle/current.xml
    sdk_rights
    base --runtime /bin/uwvm2-ros > /sdk-signatures.log 2>&1 || { cat /sdk-signatures.log; fail signed-sdk; }
    grep -Fq 'WSEA policy and signature verified for VM "sdk"' /sdk-signatures.log || fail missing-deployer-sdk-verification
    grep -Fq '"--secure", "module", "/tmp/wros-admitted.wasm", "/trust/sdk-vm.policy"' /sdk-signatures.log || fail missing-vm-sdk-verification
    test "$(sha256sum /state/sdk-admission/state)" = "$admission_state_before" || fail sdk-verifier-mutated-admission-state
    grep -Fq 'sdk|1|' /state/sdk-vm/state || fail missing-vm-sdk-rollback-record
    cat /sdk-signatures.log
    empty; pass signed-sdk-verification-at-deployer-and-vm
    if test -f /bundle/ros-interfaces.txt; then
        while read -r name; do
            decision=deny
            test "$name" != abi || decision=allow
            grep -Fxq "INFO VM \"sdk\" ROSv2 interface $name: $decision" /sdk-signatures.log || fail missing-interface-review
        done < /bundle/ros-interfaces.txt
        pass signed-sdk-reviewed-every-ros-interface
    fi
fi

if test -f /bundle/clock.signed.wasm; then
    mkdir /state/clock-admission /state/clock-vm /state/clock-review
    chmod 700 /state/clock-admission /state/clock-vm /state/clock-review
    for role in admission vm; do
        /bin/cosign wasm secure policy-init --output "/trust/clock-$role.policy" --state-dir "/state/clock-$role" --trust-root /trust/clock-root.pem --certificate /trust/clock-signer.pem --module-id split32 --algorithms Ed25519 --capabilities 1
        chmod 644 "/trust/clock-$role.policy"
    done
    chown -R 10001:10001 /state/clock-vm
    clockdigest=$(sha256sum /bundle/clock.signed.wasm); clockdigest=${clockdigest%% *}
    printf '<deployment id="cell"><vm id="clock" module="clock.signed.wasm" sha256="%s" policy="clock-admission.policy" vm-policy="clock-vm.policy" recommendations="clock-rights.xml" memory-bytes="%s" engine="interpreter" pids="16" uid="10001" gid="10001"/></deployment>\n' "$clockdigest" "$sdk_memory" > /bundle/current.xml
    set -- /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --runtime /bin/uwvm2-ros --cgroup-parent /sys/fs/cgroup/delegated --state-directory /state/clock-review
    /bin/wros-deployer authorize "$@" --accept-recommendations > /clock-authorize.log 2>&1 || { cat /clock-authorize.log; fail clock-approval; }
    printf '<recommendations/>\n' > /bundle/clock-rights.xml
    /bin/wros-deployer resume "$@" > /clock-resume.log 2>&1 || { cat /clock-resume.log; fail clock-resume; }
    grep -Fq 'split32|1|' /state/clock-vm/state || fail clock-secondary-signature-check
    empty; pass clock-cold-start-preserves-reviewed-reads
    if base --runtime /bin/uwvm2-ros > /clock-empty.log 2>&1; then fail unexpected-clock-read; fi
    grep -Fq 'clock_time_get' /clock-empty.log || { cat /clock-empty.log; fail clock-hidden-diagnostic; }
    grep -Fq 'namespace permission is disabled' /clock-empty.log || { cat /clock-empty.log; fail clock-hidden-reason; }
    empty; pass clock-empty-recommendations-start-hidden
fi

if test -f /bundle/schedule.signed.wasm; then
    digest_schedule=$(sha256sum /bundle/schedule.signed.wasm); digest_schedule=${digest_schedule%% *}
    mkdir -m 700 /state/schedule-admission /state/schedule-vm
    for role in admission vm; do
        /bin/cosign wasm secure policy-init --output "/trust/schedule-$role.policy" --state-dir "/state/schedule-$role" --trust-root /trust/root.pem --certificate /trust/signer.pem --module-id schedule --algorithms Ed25519 --capabilities 32
        chmod 644 "/trust/schedule-$role.policy"
    done
    chown -R 10001:10001 /state/schedule-vm
    for engine in interpreter aot; do
        review="/state/schedule-$engine"
        mkdir -m 700 "$review"
        cp /bundle/schedule-rights.xml /bundle/local-rights.xml
        printf '<deployment id="cell"><vm id="schedule" module="schedule.signed.wasm" sha256="%s" policy="schedule-admission.policy" vm-policy="schedule-vm.policy" recommendations="local-rights.xml" memory-bytes="%s" engine="%s" pids="16" uid="10001" gid="10001"/></deployment>\n' "$digest_schedule" "$sdk_memory" "$engine" > /bundle/current.xml
        set -- /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --runtime /bin/uwvm2-ros --cgroup-parent /sys/fs/cgroup/delegated --state-directory "$review"
        /bin/wros-deployer authorize "$@" --accept-recommendations > /schedule.log 2>&1 || { cat /schedule.log; fail schedule-approval; }
        printf '<recommendations/>\n' > /bundle/local-rights.xml
        /bin/wros-deployer resume "$@" >> /schedule.log 2>&1 || { cat /schedule.log; fail schedule-resume; }
        grep -Fq 'local guard resource "signal" operation guard.take: deny' /schedule.log || fail schedule-review
        if grep -Fq -- '--wasip1-single-create' /schedule.log; then fail unexpected-wasi-policy; fi
        grep -Fq 'schedule|1|' /state/schedule-vm/state || fail schedule-secondary-verification
        empty; pass "local-scheduling-$engine"
    done
fi

echo "$parent_limit" > /sys/fs/cgroup/delegated/memory.max || fail sdk-restore-parent-budget

configure parentdeath true 2 134217728
fixture parentdeath > /death.log 2>&1 & management=$!
wait_started /death.log 1
worker=$(cat /sys/fs/cgroup/delegated/wros-cell/vm-parentdeath/cgroup.procs)
manager=$(cat /proc/$management/task/$management/children | awk '{print $1}')
test -n "$manager" || manager=$management
kill -KILL "$manager"; wait "$management" || true
sleep .1; not_running "$worker"
if competitor 10001 11001 > /uid-dead-manager.log 2>&1; then fail dead-manager-identity-takeover; fi
grep -q 'belongs to another deployment or has an invalid record' /uid-dead-manager.log || { cat /uid-dead-manager.log; fail dead-manager-owner-lost; }
pass manager-crash-keeps-identity-with-original-deployer
if fixture parentdeath > /stale.log 2>&1; then fail reused-stale-deployment; fi
# Simulate the ultimate service supervisor reclaiming the dead manager's tree.
echo 1 > /sys/fs/cgroup/delegated/wros-cell/cgroup.kill
rmdir /sys/fs/cgroup/delegated/wros-cell/vm-parentdeath
rmdir /sys/fs/cgroup/delegated/wros-cell
pass manager-death-fences-child-and-stale-tree

# A durable approval is outside the bundle and inaccessible to every guest UID.
# These are genuine supervisor SIGKILLs and kernel cgroup recoveries, not mocked
# journal transitions. The hostile child leaves an independent grandchild alive.
mkdir /state/journal
chmod 700 /state/journal
configure stop true 2 134217728 'recommendations="permissions.xml"'
printf '<recommendations><interface name="abi" expose="deny"/></recommendations>\n' > /bundle/permissions.xml
cp /bundle/current.xml /bundle/original.xml
set -- /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --runtime /bin/supervisor-peer --state-directory /state/journal
# Independently approved stale state must not reclaim a live manager's tree.
# Both approvals are created while the deployment is inactive; their state
# directories differ. This checks admission order, not just competing spawn.
mkdir /state/second-journal; chmod 700 /state/second-journal
/bin/wros-deployer authorize /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --runtime /bin/supervisor-peer --state-directory /state/second-journal --accept-recommendations --allow-unsigned "stop=$digest" > /second-approval.log 2>&1 || { cat /second-approval.log; fail second-approval; }
mkdir /state/changed-journal; chmod 700 /state/changed-journal
/bin/busybox sed 's/uid="10001" gid="10001"/uid="12001" gid="12001"/' /bundle/current.xml > /bundle/changed-identity.xml
/bin/wros-deployer authorize /bundle/changed-identity.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --runtime /bin/supervisor-peer --state-directory /state/changed-journal --accept-recommendations --allow-unsigned "stop=$digest" > /changed-approval.log 2>&1 || { cat /changed-approval.log; fail changed-approval; }
/bin/wros-deployer run "$@" --accept-recommendations --allow-unsigned "stop=$digest" > /durable-first.log 2>&1 & manager=$!
wait_started /durable-first.log 1
sleep .1
before_pids=$(cat /sys/fs/cgroup/delegated/wros-cell/vm-stop/cgroup.procs)
before_approval=$(sha256sum /state/second-journal/approval)
if /bin/wros-deployer resume /bundle/current.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --runtime /bin/supervisor-peer --state-directory /state/second-journal > /second-resume.log 2>&1; then fail second-manager-resumed; fi
grep -q 'host identity or device is busy' /second-resume.log || { cat /second-resume.log; fail wrong-second-manager-rejection; }
test "$before_pids" = "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-stop/cgroup.procs)" || fail competing-resume-killed-original
test "$before_approval" = "$(sha256sum /state/second-journal/approval)" || fail competing-resume-consumed-approval
before_approval=$(sha256sum /state/changed-journal/approval)
if /bin/wros-deployer resume /bundle/changed-identity.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --runtime /bin/supervisor-peer --state-directory /state/changed-journal > /changed-resume.log 2>&1; then fail changed-manager-resumed; fi
grep -q 'host identity or device is busy' /changed-resume.log || { cat /changed-resume.log; fail wrong-changed-manager-rejection; }
test "$before_pids" = "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-stop/cgroup.procs)" || fail changed-identities-bypassed-deployment-lock
test "$before_approval" = "$(sha256sum /state/changed-journal/approval)" || fail changed-resume-consumed-approval
pass identity-reservation-precedes-recovery-and-approval-consumption
if /bin/wros-deployer resume "$@" > /durable-lock.log 2>&1; then fail accepted-duplicate-state-owner; fi
grep -q 'already owned by another supervisor' /durable-lock.log || { cat /durable-lock.log; fail wrong-lock-denial; }
pass state-lock-refuses-second-manager
kill -KILL "$manager"; wait "$manager" || true
sleep .1
old=$(cat /sys/fs/cgroup/delegated/wros-cell/vm-stop/cgroup.procs)
test -n "$old" || fail missing-hostile-survivor
configure stop true 2 67108864 'recommendations="permissions.xml"'
if /bin/wros-deployer resume "$@" > /durable-binding.log 2>&1; then fail accepted-changed-approval; fi
grep -q 'no matching durable approval' /durable-binding.log || { cat /durable-binding.log; fail wrong-binding-denial; }
test -n "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-stop/cgroup.procs)" || fail killed-before-binding-validation
cp /bundle/original.xml /bundle/current.xml
pass state-binding-change-rejected-before-reclaim
mkdir /sys/fs/cgroup/delegated/wros-cell/unapproved
if /bin/wros-deployer resume "$@" > /durable-unknown.log 2>&1; then fail reclaimed-unknown-group; fi
grep -q 'unapproved child cgroup' /durable-unknown.log || { cat /durable-unknown.log; fail wrong-unknown-denial; }
test -n "$(cat /sys/fs/cgroup/delegated/wros-cell/vm-stop/cgroup.procs)" || fail killed-before-subtree-validation
rmdir /sys/fs/cgroup/delegated/wros-cell/unapproved
pass state-unknown-cgroup-rejected-before-reclaim
# Editing the recommendation cannot silently change the previously approved map.
printf '<recommendations><interface name="abi" expose="allow"/></recommendations>\n' > /bundle/permissions.xml
/bin/wros-deployer resume "$@" > /durable-second.log 2>&1 & manager=$!
wait_started /durable-second.log 1
grep -q 'generation 2 started' /durable-second.log || fail lost-persisted-generation
for process in $old; do not_running "$process"; done
grep -q '"abi", "deny"' /durable-second.log || { cat /durable-second.log; fail reapplied-recommendation; }
pass state-recommendations-not-reapplied
pass state-manager-crash-reclaims-all-descendants
kill -KILL "$manager"; wait "$manager" || true
/bin/wros-deployer resume "$@" > /durable-third.log 2>&1 & manager=$!
wait_started /durable-third.log 1
grep -q 'generation 3 started' /durable-third.log || fail lost-second-generation
kill -KILL "$manager"; wait "$manager" || true
/bin/wros-deployer resume "$@" > /durable-exhausted.log 2>&1 || { cat /durable-exhausted.log; fail exhausted-resume; }
grep -q 'No instance has an automatic cold-start grant' /durable-exhausted.log || fail reset-crash-budget
empty; pass state-manager-crashes-preserve-retry-budget
# A fresh operator-reviewed invocation may reset retries, but an automatic one
# may not. Operator shutdown is committed before descendant termination.
/bin/wros-deployer run "$@" --accept-recommendations --allow-unsigned "stop=$digest" > /durable-stop.log 2>&1 & manager=$!
wait_started /durable-stop.log 1
grep -q 'generation 4 started' /durable-stop.log || fail operator-reset-generation
approval_before=$(sha256sum /state/journal/approval)
/bin/wros-deployer status --state-directory /state/journal > /durable-status.log 2>&1 || { cat /durable-status.log; fail status-during-execution; }
grep -Fxq 'INFO Recorded VM "stop" generation 4, phase running, restarts 0' /durable-status.log || fail wrong-running-phase
test "$(sha256sum /state/journal/approval)" = "$approval_before" || fail status-changed-review
kill -TERM "$manager"; wait "$manager" || { cat /durable-stop.log; fail durable-stop; }
/bin/wros-deployer status --state-directory /state/journal > /durable-status.log 2>&1 || fail status-after-stop
grep -Fxq 'INFO Recorded VM "stop" generation 4, phase stopped, restarts 0' /durable-status.log || fail wrong-stopped-phase
pass state-status-reports-running-and-stopped-without-changes
/bin/wros-deployer resume "$@" > /durable-stopped.log 2>&1 || fail stopped-resume
grep -q 'No instance has an automatic cold-start grant' /durable-stopped.log || fail restarted-after-durable-stop
empty; pass state-operator-stop-survives-manager-replacement
cp /state/journal/approval /state/journal/backup
printf X | dd of=/state/journal/approval bs=1 count=1 conv=notrunc 2>/dev/null
if /bin/wros-deployer status --state-directory /state/journal > /durable-status.log 2>&1; then fail status-accepted-corruption; fi
grep -q 'checksum mismatch' /durable-status.log || fail wrong-status-corruption-denial
if /bin/wros-deployer resume "$@" > /durable-tamper.log 2>&1; then fail accepted-corrupt-state; fi
grep -q 'checksum mismatch' /durable-tamper.log || { cat /durable-tamper.log; fail wrong-tamper-denial; }
cp /state/journal/backup /state/journal/approval
empty; pass state-record-tamper-fails-closed
chmod 755 /state/journal
if /bin/wros-deployer resume "$@" > /durable-private.log 2>&1; then fail accepted-readable-state-directory; fi
grep -q 'exclusive owner and private' /durable-private.log || fail wrong-mode-denial
chmod 700 /state/journal
empty; pass state-private-storage-required
rm /state/journal/lock
ln -s backup /state/journal/lock
if /bin/wros-deployer resume "$@" > /durable-symlink.log 2>&1; then fail followed-state-lock-symlink; fi
rm /state/journal/lock
empty; pass state-symlink-lock-refused
ln /state/journal/approval /state/journal/alias
if /bin/wros-deployer resume "$@" > /durable-hardlink.log 2>&1; then fail accepted-aliased-approval; fi
grep -q 'exclusive owner and private' /durable-hardlink.log || fail wrong-hardlink-denial
rm /state/journal/alias
empty; pass state-approval-hardlink-refused

for log in /normal.log /placement*.log /crash.log /restart.log /orphan.log /pids.log /memory.log /stop.log /flood.log /backpressure.log /signed.log /multiple.log /sdk-allow.log /sdk-deny.log /sdk-status.log /sdk-hidden.log /death.log /stale.log /durable*.log; do
    echo "AUDIT_LOG $log"; cat "$log"
done

echo QEMU_SUPERVISOR_PASS
trap - EXIT
poweroff -f
