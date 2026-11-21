#!/bin/sh
# @brief Exercise signed read-only telemetry with production admission and IPC.
set -eu
ulimit -c 0

busybox mkdir -m 700 /run/scratch
for role in admission int-success aot-success int-wrong-key; do
    busybox mkdir -m 700 "/run/$role"
    /bin/cosign wasm secure policy-init --output "/trust/$role.policy" --state-dir "/run/$role" \
        --trust-root /trust/wasm-root.pem --certificate /trust/wasm-signer.pem \
        --module-id main --algorithms Ed25519 --capabilities 32
    if test "$role" != admission; then
        busybox chmod 644 "/trust/$role.policy"
        busybox chown -R 24001:24001 "/run/$role"
    fi
done

verify() {
    /bin/wros-deployer verify "$1" --policy-root /trust \
        --cosign /bin/cosign --scratch-directory /run/scratch
}
verify /bundle/deployment.xml
echo 'CASE unitree-wsea-admission PASS'
if verify /bundle/changed.xml >/run/changed.log 2>&1; then
    exit 1
fi
busybox cat /run/changed.log
busybox grep -F 'signature rejected for "main"' /run/changed.log
echo 'CASE unitree-modified-wasm-denied PASS'

export WROS_TEST_CHILD_CGROUP_ROOT=/sys/fs/cgroup
exercise() {
    engine=$1
    mode=$2
    role="$engine-$mode"
    state="/run/$role/state"
    policy="/trust/$role.policy"
    log="/run/$role.log"
    if busybox grep -Fq 'main|1|' "$state"; then
        return 1
    fi
    for role in vm provider writer; do
        group="/sys/fs/cgroup/$role"
        busybox mkdir "$group"
        echo 536870912 > "$group/memory.max"
        echo 0 > "$group/memory.swap.max"
        echo 32 > "$group/pids.max"
    done
    /bin/provisioner /bin/uwvm2-ros /bundle/unitree-provider /bundle/controller.wasm \
        "$mode" "--runtime-$engine" "$policy" > "$log" 2>&1 || {
        busybox cat "$log"
        return 1
    }
    busybox cat "$log"
    busybox grep -Fq 'main|1|' "$state"
    for role in vm provider writer; do
        group="/sys/fs/cgroup/$role"
        test "$(busybox head -1 "$group/cgroup.events")" = 'populated 0'
        busybox grep -Fx 'oom 0' "$group/memory.events"
        busybox grep -Fx 'oom_kill 0' "$group/memory.events"
        busybox rmdir "$group"
    done
    if test "$mode" = success; then
        busybox grep -Fxq 'Go2 LowState over TLS tick=41347 position=0.125' "$log"
        echo "CASE unitree-go2-attachment-$engine PASS"
    fi
}
exercise int success
exercise aot success
exercise int wrong-key
