#!/bin/sh
# @file unitree_live_guest.sh
# @brief Run one individually reviewed signed Go2 application and driver in an offline KVM guest.
set -eu
set -o pipefail
exec </dev/console >/dev/console 2>&1
ulimit -c 0
b=/bin/busybox
failed() {
    test ! -f /run/application.log || "$b" cat /run/application.log
    echo WROS_UNITREE_LIVE_FAILED
    "$b" poweroff -f
}
trap failed EXIT
"$b" mount -t proc proc /proc
"$b" mount -t sysfs sysfs /sys
"$b" mount -t cgroup2 none /sys/fs/cgroup
test "$("$b" ls /sys/class/net)" = lo
"$b" mknod -m 0444 /dev/zero c 1 5
"$b" mknod -m 0444 /dev/random c 1 8
"$b" mknod -m 0444 /dev/urandom c 1 9
"$b" mknod -m 0666 /dev/ptmx c 5 2
"$b" mkdir /dev/pts
"$b" mount -t devpts devpts /dev/pts
"$b" mkdir -m 700 /run/scratch /run/vm /run/admission
g=/sys/fs/cgroup
"$b" mkdir "$g/manager" "$g/workloads"
echo $$ > "$g/manager/cgroup.procs"
echo '+cpu +memory +pids' > "$g/cgroup.subtree_control"
echo '+cpu +memory +pids' > "$g/workloads/cgroup.subtree_control"
echo 1073741824 > "$g/workloads/memory.max"
echo 0 > "$g/workloads/memory.swap.max"

profile=
for arg in $("$b" cat /proc/cmdline); do
    case "$arg" in wros_case=*) profile=${arg#wros_case=} ;; esac
done
case "$profile" in
    profile-default) request=24; response=24 ;;
    reply-128) request=24; response=128 ;;
    request-128-reply-1024) request=128; response=1024 ;;
    *) exit 1 ;;
esac
read -r module algorithm </etc/wasm-identity
for role in admission vm; do
    /bin/cosign wasm secure policy-init --output "/trust/$role.policy" --state-dir "/run/$role" \
        --trust-root /trust/app-root.pem --certificate /trust/app-signer.pem \
        --module-id "$module" --algorithms "$algorithm" --capabilities 32
done
"$b" chmod 644 /trust/vm.policy
"$b" chown -R 24101:24101 /run/vm
before_a=$("$b" sha256sum /run/admission/state)
before_v=$("$b" sha256sum /run/vm/state)

# The PTY helper types the explicit confirmation for this disposable fixture.
set -- /bin/wros-deployer run "/bundle/$profile/deployment.xml" --policy-root /trust \
    --runtime /bin/uwvm2-ros --cosign /bin/cosign --elf-verifier /bin/uwvm2-ros \
    --driver-root /sandboxes --cgroup-parent "$g/workloads" --scratch-directory /run/scratch \
    --accept-recommendations-through-risk --risk-accept-threshold 10
/bin/review-terminal "$@" 2>&1 | "$b" cat > /run/application.log &
manager=$!
group="$g/workloads/wros-unitree"
confined=false
for unused in $("$b" seq 1500); do
    driver=$("$b" head -1 "$group/driver-unitree/cgroup.procs" 2>/dev/null || true)
    vm=$("$b" head -1 "$group/vm-$module/cgroup.procs" 2>/dev/null || true)
    if test -n "$driver" && test -n "$vm"; then
        driver_net=$("$b" readlink "/proc/$driver/ns/net" || true)
        vm_net=$("$b" readlink "/proc/$vm/ns/net" || true)
        driver_ipc=$("$b" readlink "/proc/$driver/ns/ipc" || true)
        vm_ipc=$("$b" readlink "/proc/$vm/ns/ipc" || true)
        if test -n "$driver_net" && test -n "$vm_net" && test "$driver_net" != "$vm_net" && \
           test -n "$driver_ipc" && test -n "$vm_ipc" && test "$driver_ipc" != "$vm_ipc" && \
           test "$("$b" readlink "/proc/$driver/root" || true)" = /sandboxes/go2 && \
           "$b" grep -Eq '^Uid:[[:space:]]+24102[[:space:]]+24102[[:space:]]' "/proc/$driver/status" && \
           "$b" grep -Eq '^Uid:[[:space:]]+24101[[:space:]]+24101[[:space:]]' "/proc/$vm/status" && \
           "$b" grep -Eq '^Seccomp:[[:space:]]+2$' "/proc/$driver/status" && \
           "$b" grep -Eq '^Seccomp:[[:space:]]+2$' "/proc/$vm/status"; then
            echo "ISOLATION driver=$driver uid=24102 net=$driver_net ipc=$driver_ipc root=/sandboxes/go2 vm=$vm uid=24101 net=$vm_net ipc=$vm_ipc"
            confined=true
            break
        fi
    fi
    "$b" kill -0 "$manager" 2>/dev/null || break
    "$b" sleep 0.02
done
status=0
wait "$manager" || status=$?
test "$status" = 0 && test "$confined" = true || exit 1
log=/run/application.log
"$b" grep -Fq "contract-bounded buffer.read payload ceilings: request $request bytes, response $response bytes, request deadline 2000 ms." "$log"
"$b" grep -Fq "Review effective decisions for VM \"$module\"" "$log"
"$b" grep -Fq 'Type "deploy unitree" to proceed: INFO Starting reviewed VM deployment' "$log"
"$b" grep -Fq "WSEA policy and signature verified for VM \"$module\"" "$log"
"$b" grep -Fq 'Driver "unitree" passed launch signature policy Verified' "$log"
"$b" grep -Fq "VM \"$module\" native driver \"go2-state\" buffer.read: allow" "$log"
for op in clock.create clock.read; do
    "$b" grep -Fq "VM \"$module\" local clock.steady resource \"steady\" operation $op: allow" "$log"
done
"$b" grep -Fq "VM \"$module\" generation 1 exit exit status: 0" "$log"
test "$before_a" = "$("$b" sha256sum /run/admission/state)"
test "$before_v" != "$("$b" sha256sum /run/vm/state)"
test ! -e "$group"
"$b" cat "$log"
echo "WROS_UNITREE_LIVE_PASS $profile"
trap - EXIT
"$b" poweroff -f
