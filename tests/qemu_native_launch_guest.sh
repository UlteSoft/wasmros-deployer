#!/bin/sh
# @file qemu_native_launch_guest.sh
# @brief Review and exercise signed production driver launches with a recorded Go2 fixture.
set -eu
set -o pipefail
exec </dev/console >/dev/console 2>&1
ulimit -c 0
b=/bin/busybox
trap 'for log in /run/*.log /run/*.sensor; do test ! -f "$log" || $b tail -n 40 "$log"; done; echo WROS_NATIVE_LAUNCH_FAILED; $b poweroff -f' EXIT
$b mount -t proc proc /proc
$b mount -t sysfs sysfs /sys
$b mount -t cgroup2 none /sys/fs/cgroup
$b mknod -m 0444 /dev/zero c 1 5
$b mknod -m 0444 /dev/random c 1 8
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

roles="admission vm"
if test -f /bundle/sdk-imports.txt; then
    roles="$roles sdk-signed sdk-signed-int"
fi
for role in $roles; do
    $b mkdir -p -m 700 "/run/$role"
    /bin/cosign wasm secure policy-init --output "/trust/$role.policy" \
        --state-dir "/run/$role" --trust-root /trust/wasm-root.pem \
        --certificate /trust/wasm-signer.pem --module-id main --algorithms ES384 --capabilities 32
    if test "$role" != admission; then
        $b chmod 644 "/trust/$role.policy"
        $b chown -R 24101:24101 "/run/$role"
    fi
done

elf_check=/bin/uwvm2-ros
# The PTY relay exits just after the deployer. Reading the pipe through EOF
# makes subsequent log checks deterministic and pipefail preserves its status.
command() {
    manifest=$1
    shift
    "$@" /bin/wros-deployer run "/bundle/$manifest.xml" --policy-root /trust \
        --runtime /bin/uwvm2-ros --cosign /bin/cosign --scratch-directory /run/scratch \
        --elf-verifier "$elf_check" --driver-root /sandboxes \
        --cgroup-parent "$g/workloads" --accept-recommendations-through-risk --risk-accept-threshold 10 2>&1 | "$b" cat
}
run() {
    manifest=$1
    shift
    /bin/review-terminal /bin/wros-deployer run "/bundle/$manifest.xml" --policy-root /trust \
        --runtime /bin/uwvm2-ros --cosign /bin/cosign --scratch-directory /run/scratch \
        --elf-verifier "$elf_check" --driver-root /sandboxes \
        --cgroup-parent "$g/workloads" --accept-recommendations-through-risk --risk-accept-threshold 10 "$@" 2>&1 | "$b" cat
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

# The offline fixture owns the original SDK network. Capture an authentic sample
# before starting the managed provider, whose work uses only the assigned carrier.
$b ip link set lo up
(
    echo 0 > "$g/sensor/cgroup.procs"
    export LD_LIBRARY_PATH=/opt/unitree
    exec "$b" su -s /bin/sh -c 'LD_LIBRARY_PATH=/opt/unitree exec /bin/low-state publish' writer
) > /run/official-publisher.log 2>&1 &
publisher=$!
(
    echo 0 > "$g/sensor/cgroup.procs"
    exec "$b" su -s /bin/sh -c 'LD_LIBRARY_PATH=/opt/unitree exec /bin/low-state read' writer
) > /run/official-reader.log
wait "$publisher"
$b grep -x 'Go2 LowState tick=41347 position=0.125' /run/official-reader.log > /sandboxes/go2/telemetry.txt
$b chmod 0444 /sandboxes/go2/telemetry.txt
echo 'CASE original-sdk-recorded-sample PASS'

exercise() {
    label=$1
    shift
    sdk_state=
    if test -f /bundle/sdk-imports.txt && { test "$label" = signed || test "$label" = signed-int; }; then
        sdk_state="/run/sdk-$label/state"
        test -f "$sdk_state"
        if $b grep -Fq 'main|1|' "$sdk_state"; then exit 1; fi
        admission_before=$($b sha256sum /run/admission/state)
    fi
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
    # Cgroup membership is assigned before chroot and namespace setup. Inspect
    # the settled workload identities and both live namespace links together.
    confined=false
    for _ in $($b seq 150); do
        vm=$($b head -n 1 "$vm_group/cgroup.procs" 2>/dev/null || true)
        if test -n "$vm"; then
            driver_net=$($b readlink "/proc/$driver/ns/net" || true)
            vm_net=$($b readlink "/proc/$vm/ns/net" || true)
            driver_root=$($b readlink "/proc/$driver/root" || true)
            if test -n "$driver_net" && test -n "$vm_net" && test "$driver_net" != "$vm_net" &&
               test "$driver_root" = /sandboxes/go2 &&
               $b grep -Eq '^Uid:[[:space:]]+24101[[:space:]]+24101[[:space:]]' "/proc/$vm/status"; then
                confined=true
                break
            fi
        fi
        $b sleep 0.02
    done
    if test "$confined" != true; then
        echo "No settled workload namespace observation for $label"
        $b cat "/run/$label.log"
        exit 1
    fi
    if ! wait "$manager"; then
        $b cat "/run/$label.log"
        exit 1
    fi
    $b cat "/run/$label.log"
    $b grep -F 'Driver "unitree" passed launch signature policy' "/run/$label.log"
    $b grep -F 'Managed driver endpoint creation denied' "/run/$label.log"
    $b grep -F 'Go2 LowState over TLS tick=41347 position=0.125' "/run/$label.log"
    $b grep -F 'Review effective decisions for VM "main"' "/run/$label.log"
    $b grep -F 'adopting scored recommendations at or below 10/10' "/run/$label.log"
    if test -n "$sdk_state"; then
        $b grep -Fq 'WSEA policy and signature verified for VM "main"' "/run/$label.log"
        $b grep -Fq 'main|1|' "$sdk_state"
        test "$($b sha256sum /run/admission/state)" = "$admission_before"
        while read -r name; do
            $b grep -Fq "imports \"uwvm_ros_v2\" \"$name\"" "/run/$label.log"
            $b grep -Fq "VM \"main\" ROSv2 interface $name: allow" "/run/$label.log"
        done < /bundle/sdk-imports.txt
        echo "CASE unitree-sdk-$label PASS"
    fi
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
if test -f /bundle/payload-default.xml; then
    for label in payload-default payload-reply payload-large; do
        case "$label" in
            payload-default) request=24; response=24 ;;
            payload-reply) request=24; response=128 ;;
            payload-large) request=128; response=1024 ;;
        esac
        exercise "$label"
        "$b" grep -Fq "request $request bytes, response $response bytes, request deadline 2000 ms." "/run/$label.log"
        for op in clock.create clock.read; do
            "$b" grep -Fq "local clock.steady resource \"steady\" operation $op: allow" "/run/$label.log"
        done
    done
fi
elf_check=/bin/test-elf-verifier
echo test > /run/replace-image
exercise sealed-replacement
$b grep -F 'source name no longer refers' /bundle/swap-provider
echo WROS_NATIVE_LAUNCH_PASS
trap - EXIT
$b poweroff -f
