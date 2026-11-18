#!/bin/sh
# Privileged tests run only inside an offline disposable QEMU guest.
set -eu
export PATH=/bin:/usr/bin SYSTEMD_PAGER=cat SYSTEMD_COLORS=0
fail() { echo "QEMU_SERVICE_FAIL $*"; journalctl --no-pager -n 80 -o cat || true; poweroff -f; exit 1; }
trap 'fail unexpected-command-failure' EXIT
pass() { echo "CASE $1 PASS"; }
echo "SERVICE_SYSTEMD $(systemctl --version | head -1)"
case_uid=20000

configure() {
    caseid=$1; vmid=$2; crash=$3; limit=$4; image=${5:-unsigned.wasm}; runtime=${6:-/bin/supervisor-peer}
    case_uid=$((case_uid+1))
    digest=$(sha256sum /bundle/$image); digest=${digest%% *}
    unit=wros-$caseid.service; cg=/sys/fs/cgroup/system.slice/$unit
    manifest=/bundle/$caseid.xml; state=/state/$caseid; program=/bin/wros-deployer
    mkdir -p /state/$caseid; chmod 700 /state/$caseid
    printf '<deployment id="%s"><supervisor memory-bytes="268435456" pids="64" cpu-micros="50000" cpus="0" memory-nodes="0"/><vm id="%s" module="%s" sha256="%s" policy="body.policy" memory-bytes="134217728" pids="8" uid="%s" gid="%s" restart-on-crash="%s" restart-limit="%s" restart-delay-ms="100" cpus="1" memory-nodes="1"/></deployment>\n' "$caseid" "$vmid" "$image" "$digest" "$case_uid" "$case_uid" "$crash" "$limit" > /bundle/$caseid.xml
}
command() {
    "$program" "$1" "$manifest" --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --runtime "$runtime" --state-directory "$state" --supervisor-cgroup "$cg" ${2:+"$2"} ${3:+"$3"} ${4:+"$4"}
}
authorize() { command authorize --accept-recommendations --allow-unsigned "$vmid=$digest" > /$caseid-review.log 2>&1 || { cat /$caseid-review.log; fail authorization; }; }
install() {
    command service > /etc/systemd/system/$unit
    systemctl daemon-reload
}
logs() { journalctl --no-pager -u "$unit" -o cat > /$caseid.log; }
wait_started() {
    count=$1; loops=0
    while :; do
        logs
        test "$(grep -c 'started with PID' /$caseid.log || true)" -ge "$count" && break
        loops=$((loops+1)); test "$loops" -lt 400 || { cat /$caseid.log; fail start-timeout; }
        sleep .025
    done
}
wait_ended() {
    loops=0
    while :; do
        active=$(systemctl show -p ActiveState --value "$unit")
        case "$active" in inactive|failed) break;; esac
        loops=$((loops+1)); test "$loops" -lt 400 || fail end-timeout
        sleep .025
    done
}
not_running() {
    for pid in "$@"; do
        if test -f /proc/$pid/stat; then
            test "$(cut -d ' ' -f3 /proc/$pid/stat)" = Z || fail "old-process-$pid-survived"
        fi
    done
}

# Rendering creates no deployment and resume cannot synthesize permission.
configure missing normal false 0
install
test ! -e /state/$caseid/approval || fail render-created-authority
systemctl start "$unit" || true
wait_ended; logs
grep -q 'no matching durable approval' /$caseid.log || fail missing-approval-not-rejected
test "$(systemctl show -p NRestarts --value "$unit")" = 0 || fail configuration-restart-loop
pass service-never-creates-approval

configure quoted normal false 0
program='/bin/wros $TOKEN %n'
cp /bin/wros-deployer "$program"
state='/state/quoted $TOKEN %n'; mkdir "$state"; chmod 700 "$state"
manifest='/bundle/quoted $TOKEN %n.xml'; cp /bundle/quoted.xml "$manifest"
authorize; install; systemctl start "$unit"; wait_ended; logs
grep -q 'PEER confined' /$caseid.log || { cat /etc/systemd/system/$unit; fail systemd-argument-expansion; }
pass service-arguments-preserve-spaces-dollar-and-percent

# Authorize once, with recovery disabled: the independent service may start it.
configure single parentdeath false 0
authorize; install
test ! -d "$cg" || fail approval-created-cgroup
before=$(sha256sum "$state/approval")
if command resume > /wrong-context.log 2>&1; then fail foreign-service-accepted; fi
grep -q 'exact manager subgroup' /wrong-context.log || fail incorrect-context-rejection
test "$before" = "$(sha256sum "$state/approval")" || fail authority-consumed-on-context-rejection
pass foreign-supervisor-context-rejected-before-authority-consumption
systemctl start "$unit"; wait_started 1
manager=$(systemctl show -p MainPID --value "$unit")
child=$(cat "$cg/workloads/wros-$caseid/vm-$vmid/cgroup.procs")
test "$(cat "$cg/manager/memory.max")" = 268435456 || fail manager-memory
test "$(cat "$cg/manager/pids.max")" = 64 || fail manager-tasks
test "$(cat "$cg/manager/cpu.max")" = '50000 100000' || fail manager-cpu
test "$(cat "$cg/workloads/memory.max")" = 134217728 || fail workload-memory
grep -q 'Cpus_allowed_list:[[:space:]]*0$' /proc/$manager/status || fail manager-cpuset
grep -q 'Mems_allowed_list:[[:space:]]*0$' /proc/$manager/status || fail manager-numa
grep -q 'Cpus_allowed_list:[[:space:]]*1$' /proc/$child/status || fail vm-cpuset
grep -q 'Mems_allowed_list:[[:space:]]*1$' /proc/$child/status || fail vm-numa
pass manager-and-workload-resource-separation
kill -KILL "$manager"
sleep 2; wait_ended; logs
test "$(grep -c 'started with PID' /$caseid.log)" = 1 || fail implicit-recovery
not_running "$manager" "$child"
pass first-start-does-not-grant-crash-recovery

# An orphan explicitly ignores TERM; systemd must clear it before the next manager.
configure recovery stop true 1
authorize; install; systemctl start "$unit"; wait_started 1
manager=$(systemctl show -p MainPID --value "$unit")
sleep .1; old=$(cat "$cg/workloads/wros-$caseid/vm-$vmid/cgroup.procs")
test "$(printf '%s\n' "$old" | wc -l)" -ge 2 || fail orphan-missing
kill -KILL "$manager"; wait_started 2
not_running $old "$manager"
pass independent-supervisor-clears-orphans-before-restart
manager=$(systemctl show -p MainPID --value "$unit")
kill -KILL "$manager"; sleep 2; wait_ended; logs
test "$(grep -c 'started with PID' /$caseid.log)" = 2 || fail persistent-retry-bound
test ! -d "$cg" || test "$(cat "$cg/cgroup.events" | head -1)" = 'populated 0' || fail retry-leftovers
pass manager-restarts-cannot-reset-retry-budget

# Manual stop is persisted and a subsequent automatic invocation remains idle.
configure manual stop true 3
authorize; install; systemctl start "$unit"; wait_started 1
old=$(cat "$cg/workloads/wros-$caseid/vm-$vmid/cgroup.procs")
systemctl stop "$unit"; not_running $old
systemctl start "$unit"; wait_ended; logs
test "$(grep -c 'started with PID' /$caseid.log)" = 1 || fail restart-after-manual-stop
pass manual-service-stop-retains-stopped-authority

# A real VM (not the native fixture) runs under this same service boundary.
configure wasm body true 1 loop.wasm /bin/uwvm2-ros
authorize; install; systemctl start "$unit"; wait_started 1
child=$(cat "$cg/workloads/wros-$caseid/vm-$vmid/cgroup.procs")
test -e /proc/$child/exe || fail real-vm-missing
sleep .2; not_exited=$(cat "$cg/workloads/wros-$caseid/vm-$vmid/cgroup.procs")
test "$not_exited" = "$child" || fail real-vm-exited
logs; test "$(grep -c 'generation 1 exit' /$caseid.log || true)" = 0 || fail real-vm-rejected-image
systemctl stop "$unit"; not_running "$child"
pass actual-vm-under-systemd

# An incompatible platform layout or reduced outer budget must fail before VM exec.
configure layout normal false 0
authorize; install
mkdir -p /etc/systemd/system/$unit.d
printf '[Service]\nDelegateSubgroup=wrong\n' > /etc/systemd/system/$unit.d/fault.conf
systemctl daemon-reload; systemctl start "$unit" || true; wait_ended; logs
grep -q 'exact manager subgroup' /$caseid.log || fail wrong-layout-accepted
test "$(grep -c 'started with PID' /$caseid.log || true)" = 0 || fail wrong-layout-executed
pass missing-platform-layout-fails-closed
printf '[Service]\nMemoryMax=268435456\n' > /etc/systemd/system/$unit.d/fault.conf
systemctl daemon-reload; systemctl start "$unit" || true; wait_ended; logs
grep -q 'below the reviewed service budget' /$caseid.log || fail outer-budget-accepted
pass insufficient-supervisor-budget-fails-closed
printf '[Service]\nExecStartPre=/bin/mkdir %s/unapproved\n' "$cg" > /etc/systemd/system/$unit.d/fault.conf
systemctl daemon-reload; systemctl start "$unit" || true; wait_ended; logs
grep -q 'unexpected child in the delegated service root' /$caseid.log || fail foreign-child-accepted
pass unknown-service-subtree-fails-before-execution

# Fault injection affects only the disposable manager cgroup: page-cache growth
# exceeds its hard limit and group OOM kills the manager. Work is cold restarted
# once through persisted approval after the independent supervisor drains it.
configure oom stop true 1
authorize; install; systemctl start "$unit"; wait_started 1
old=$(cat "$cg/workloads/wros-$caseid/vm-$vmid/cgroup.procs")
manager=$(systemctl show -p MainPID --value "$unit")
/bin/sh -c 'echo $$ > "$1/manager/cgroup.procs"; exec /bin/dd if=/dev/zero of=/oom-payload bs=1M count=512' sh "$cg" > /oom-injection.log 2>&1 & injector=$!
wait "$injector" && fail manager-oom-not-triggered
rm -f /oom-payload
wait_started 2; not_running $old "$manager"
pass manager-oom-is-recovered-by-independent-supervisor
systemctl stop "$unit"

# The same production boundary accepts a non-systemd platform supervisor which
# explicitly creates and owns the bounded root. This shell is a test substitute,
# not a qualified industrial replacement for the independent service manager.
configure fallback parentdeath false 0
cg=/sys/fs/cgroup/platform-test
mkdir "$cg" "$cg/manager"
echo 406847488 > "$cg/memory.max"
echo 0 > "$cg/memory.swap.max"
echo 76 > "$cg/pids.max"
authorize
/bin/sh -c 'echo $$ > "$1/manager/cgroup.procs"; exec /bin/wros-deployer resume "$2" --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --runtime /bin/supervisor-peer --state-directory "$3" --supervisor-cgroup "$1"' sh "$cg" "$manifest" "$state" > /fallback.log 2>&1 & manager=$!
loops=0
while ! grep -q 'started with PID' /fallback.log; do
    loops=$((loops+1)); test "$loops" -lt 400 || { cat /fallback.log; fail fallback-timeout; }; sleep .025
done
test "$(cat "$cg/manager/memory.max")" = 268435456 || fail fallback-unbounded
kill -TERM "$manager"; wait "$manager" || { cat /fallback.log; fail fallback-stop; }
grep -q 'populated 0' "$cg/cgroup.events" || fail fallback-leftovers
rmdir "$cg/workloads" "$cg/manager" "$cg"
pass alternate-platform-supervisor-layout

echo QEMU_SERVICE_PASS
trap - EXIT
poweroff -f
