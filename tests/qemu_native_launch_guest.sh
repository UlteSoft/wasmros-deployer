#!/bin/sh
set -eu
exec </dev/console >/dev/console 2>&1
ulimit -c 0
b=/bin/busybox
trap 'for log in /run/*.log /run/*.sensor; do test ! -f "$log" || $b tail -n 40 "$log"; done; echo WROS_NATIVE_LAUNCH_FAILED; $b poweroff -f' EXIT
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t cgroup2 none /sys/fs/cgroup
$b mknod -m 0444 /dev/urandom c 1 9
$b mknod -m 0666 /dev/ptmx c 5 2
$b mkdir /dev/pts
$b mount -t devpts devpts /dev/pts
$b mkdir -m 700 /run/scratch /run/vm
g=/sys/fs/cgroup
$b mkdir "$g/manager" "$g/workloads" "$g/sensor"
echo $$ > "$g/manager/cgroup.procs"
echo '+cpu +memory +pids' > "$g/cgroup.subtree_control"
echo '+cpu +memory +pids' > "$g/workloads/cgroup.subtree_control"
echo 1073741824 > "$g/workloads/memory.max"
echo 0 > "$g/workloads/memory.swap.max"
echo 134217728 > "$g/sensor/memory.max"
echo 0 > "$g/sensor/memory.swap.max"
echo 32 > "$g/sensor/pids.max"

for role in admission vm; do
    /bin/cosign wasm secure policy-init --output "/trust/$role.policy" \
        --state-dir "/run/$role" --trust-root /trust/wasm-root.pem \
        --certificate /trust/wasm-signer.pem --module-id main --algorithms ES384 --capabilities 32
done
$b chmod 644 /trust/vm.policy
$b chown -R 24101:24101 /run/vm

elf_check=/bin/uwvm2-ros
command() {
    manifest=$1
    shift
    "$@" /bin/wros-deployer run "/bundle/$manifest.xml" --policy-root /trust \
        --runtime /bin/uwvm2-ros --cosign /bin/cosign --scratch-directory /run/scratch \
        --elf-verifier "$elf_check" --driver-root /sandboxes \
        --cgroup-parent "$g/workloads" --accept-recommendations
}
run() {
    manifest=$1
    shift
    /bin/review-terminal /bin/wros-deployer run "/bundle/$manifest.xml" --policy-root /trust \
        --runtime /bin/uwvm2-ros --cosign /bin/cosign --scratch-directory /run/scratch \
        --elf-verifier "$elf_check" --driver-root /sandboxes \
        --cgroup-parent "$g/workloads" --accept-recommendations "$@"
}

# Failure precedes any native process or deployment cgroup creation.
if command signed </dev/null >/run/no-terminal.log 2>&1; then exit 1; fi
$b grep -F 'interactive review requires stdin, stdout and stderr on the same terminal' /run/no-terminal.log
test ! -e "$g/workloads/wros-unitree"
echo 'CASE rejects-noninteractive-review PASS'
if command signed /bin/review-terminal --fixture-cancel >/run/cancelled.log 2>&1; then exit 1; fi
$b grep -F 'deployment was not confirmed' /run/cancelled.log
test ! -e "$g/workloads/wros-unitree"
echo 'CASE cancelled-review-does-not-start PASS'
if run unsigned >/run/unsigned.log 2>&1; then exit 1; fi
$b grep -F 'Unsigned ELF signature rejected for "unitree"' /run/unsigned.log
test ! -e "$g/workloads/wros-unitree"
echo 'CASE rejects-unsigned-by-default PASS'
if run invalid >/run/invalid.log 2>&1; then exit 1; fi
$b grep -F 'Invalid ELF signature rejected for "unitree"' /run/invalid.log
test ! -e "$g/workloads/wros-unitree"
echo 'CASE rejects-invalid-by-default PASS'
if run unsigned --allow-unsigned-elf "other=$($b cat /bundle/unsigned.sha)" >/run/wrong-id.log 2>&1; then exit 1; fi
$b grep -F 'ELF signature exception does not match a driver and digest' /run/wrong-id.log
echo 'CASE rejects-wrong-exception-id PASS'
if run unsigned --allow-unsigned-elf "unitree=$($b cat /bundle/signed.sha)" >/run/wrong-digest.log 2>&1; then exit 1; fi
$b grep -F 'ELF signature exception does not match a driver and digest' /run/wrong-digest.log
echo 'CASE rejects-wrong-exception-digest PASS'
if run invalid --allow-unsigned-elf "unitree=$($b cat /bundle/invalid.sha)" >/run/wrong-kind.log 2>&1; then exit 1; fi
$b grep -F 'Invalid ELF signature rejected for "unitree"' /run/wrong-kind.log
echo 'CASE rejects-wrong-exception-kind PASS'
if run permission-denied >/run/denied.log 2>&1; then exit 1; fi
$b grep -F 'requires separate reviewed driver permission' /run/denied.log
test ! -e "$g/workloads/wros-unitree"
echo 'CASE requires-per-driver-permission PASS'
elf_check=/bin/test-elf-verifier
echo test > /run/withdraw-signer
if run signer-withdrawn >/run/withdrawn.log 2>&1; then exit 1; fi
$b grep -F 'passed launch signature policy' /run/withdrawn.log && exit 1
$b grep -F 'could not revalidate the reviewed deployment before launch' /run/withdrawn.log
test ! -e "$g/workloads/wros-unitree"
echo 'CASE withdrawn-signer-denied-before-exec PASS'
elf_check=/bin/uwvm2-ros

exercise() {
    label=$1
    shift
    run "$label" "$@" >"/run/$label.log" 2>&1 &
    manager=$!
    driver_group="$g/workloads/wros-unitree/driver-unitree"
    vm_group="$g/workloads/wros-unitree/vm-main"
    driver=
    vm=
    for _ in $($b seq 100); do
        if test -f "$driver_group/cgroup.procs"; then
            driver=$($b head -n 1 "$driver_group/cgroup.procs")
            test -z "$driver" || break
        fi
        $b kill -0 "$manager" || break
        $b sleep 0.02
    done
    if test -z "$driver"; then
        $b cat "/run/$label.log"
        exit 1
    fi
    # Inject read-only telemetry from an independent process only into the
    # test namespace. The production deployer supplies no host network.
    (
        echo 0 > "$g/sensor/cgroup.procs"
        export LD_LIBRARY_PATH=/opt/unitree
        exec $b nsenter --net="/proc/$driver/ns/net" "$b" su -s /bin/sh \
            -c 'LD_LIBRARY_PATH=/opt/unitree exec /bin/low-state publish' writer
    ) >"/run/$label.sensor" 2>&1 &
    sensor=$!
    for _ in $($b seq 100); do
        test ! -f "$vm_group/cgroup.procs" || vm=$($b head -n 1 "$vm_group/cgroup.procs")
        test -z "${vm:-}" || break
        $b sleep 0.02
    done
    test -n "${vm:-}"
    test "$($b readlink "/proc/$driver/ns/net")" != "$($b readlink "/proc/$vm/ns/net")"
    test "$($b readlink "/proc/$driver/root")" = "/sandboxes/go2"
    if ! wait "$manager"; then
        $b cat "/run/$label.log" "/run/$label.sensor"
        exit 1
    fi
    wait "$sensor"
    $b cat "/run/$label.log"
    $b grep -F 'Driver "unitree" passed launch signature policy' "/run/$label.log"
    $b grep -F 'Go2 LowState over TLS tick=41347 position=0.125' "/run/$label.log"
    $b grep -F 'Review effective decisions for VM "main"' "/run/$label.log"
    $b grep -F 'adopting parsed recommendations without per-VM edits' "/run/$label.log"
    if test "$label" = signed; then
        $b grep -F 'Risk report deployment configuration (threshold >=5/10)' "/run/$label.log"
        $b grep -F 'read-only sandbox "go2": 7/10 (high)' "/run/$label.log"
    elif test "$label" = signed-int; then
        if $b grep -F 'Risk report' "/run/$label.log"; then exit 1; fi
    fi
    test ! -e "$g/workloads/wros-unitree"
    echo "CASE production-$label PASS"
}

exercise signed
exercise signed-int --risk-report none
exercise unsigned --allow-unsigned-elf "unitree=$($b cat /bundle/unsigned.sha)"
exercise invalid --allow-invalid-elf-signature "unitree=$($b cat /bundle/invalid.sha)"
elf_check=/bin/test-elf-verifier
echo test > /run/replace-image
exercise sealed-replacement
$b grep -F 'source name no longer refers' /bundle/swap-provider
echo WROS_NATIVE_LAUNCH_PASS
trap - EXIT
$b poweroff -f
