#!/bin/sh
# This image is used only with a newly created 64 MiB virtual disk in .tmp.
set -eu
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
fail() { echo "QEMU_POWERLOSS_FAIL $*"; poweroff -f; exit 1; }
trap 'fail unexpected-command-failure' EXIT
for module in /modules/*.ko; do insmod "$module"; done
mkdir /persist
mount -t ext4 /dev/vda /persist
chmod 700 /persist
phase=0
for arg in $(cat /proc/cmdline); do case "$arg" in wros_boot_phase=*) phase=${arg#*=};; esac; done
echo "BOOT_ID $(cat /proc/sys/kernel/random/boot_id) PHASE $phase"
mkdir -p /scratch /state/admission /state/body /persist/journal
chmod 700 /scratch /state/admission /state/body /persist/journal
/bin/cosign wasm secure policy-init --output /trust/body.policy --state-dir /state/admission --trust-root /trust/root.pem --certificate /trust/signer.pem --module-id body --algorithms Ed25519
chmod 644 /trust/body.policy
mount -t cgroup2 none /sys/fs/cgroup
echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/delegated
echo 1073741824 > /sys/fs/cgroup/delegated/memory.max
echo 0 > /sys/fs/cgroup/delegated/memory.swap.max
echo 128 > /sys/fs/cgroup/delegated/pids.max
echo '+cpu +memory +pids' > /sys/fs/cgroup/delegated/cgroup.subtree_control
digest=$(sha256sum /bundle/loop.wasm); digest=${digest%% *}
printf '<deployment id="boot"><vm id="one" module="loop.wasm" sha256="%s" policy="body.policy" memory-bytes="268435456" pids="16" uid="10001" gid="10001" start-on-boot="true" restart-on-crash="false" restart-delay-ms="100"/><vm id="two" module="loop.wasm" sha256="%s" policy="body.policy" memory-bytes="268435456" pids="16" uid="10002" gid="10002" start-on-boot="false" restart-on-crash="true" restart-delay-ms="100"/></deployment>\n' "$digest" "$digest" > /bundle/boot.xml
set -- /bundle/boot.xml --policy-root /trust --cosign /bin/cosign --scratch-directory /scratch --cgroup-parent /sys/fs/cgroup/delegated --runtime /bin/uwvm2-ros --state-directory /persist/journal
if test "$phase" = 1; then
    /bin/review-terminal /bin/wros-deployer run "$@" --accept-recommendations --allow-unsigned "one=$digest" --allow-unsigned "two=$digest" > /run.log 2>&1 & manager=$!
    expected=2
else
    /bin/wros-deployer resume "$@" > /run.log 2>&1 & manager=$!
    expected=1
fi
loops=0
while test "$(grep -c 'started with PID' /run.log || true)" -lt "$expected"; do
    loops=$((loops+1)); test "$loops" -lt 300 || { cat /run.log; fail start-timeout; }
    sleep .02
done
cat /run.log
if test "$phase" = 1; then
    test -d /sys/fs/cgroup/delegated/wros-boot/vm-two || fail second-vm-absent
    # Deliberately no sync, stop, unmount, guest reboot or graceful QEMU quit.
    # The host kills this QEMU process after observing the durable start marker.
    echo QEMU_POWERLOSS_READY_TO_CUT
    while :; do sleep 1; done
fi
test ! -d /sys/fs/cgroup/delegated/wros-boot/vm-two || fail boot-without-grant
grep -q "generation $phase started" /run.log || fail generation-was-reset
kill -TERM "$manager"; wait "$manager" || fail manual-stop
test ! -d /sys/fs/cgroup/delegated/wros-boot || fail surviving-stopped-tree
/bin/wros-deployer resume "$@" > /stopped.log 2>&1 || { cat /stopped.log; fail stopped-resume; }
grep -q 'No instance has an automatic cold-start grant' /stopped.log || fail manual-stop-was-lost
if test "$phase" = 3; then
    before=$(sha256sum /persist/journal/approval)
    dd if=/dev/zero of=/persist/fill bs=1048576 count=70 2>/dev/null || true
    if /bin/wros-deployer resume "$@" > /full.log 2>&1; then fail ignored-full-durable-storage; fi
    grep -q 'No space left on device' /full.log || { cat /full.log; fail wrong-full-storage-rejection; }
    after=$(sha256sum /persist/journal/approval)
    test "$before" = "$after" || fail damaged-previous-approval
    test ! -d /sys/fs/cgroup/delegated/wros-boot || fail started-without-durable-record
    rm /persist/fill
    /bin/wros-deployer resume "$@" > /after-full.log 2>&1 || { cat /after-full.log; fail valid-record-after-enospc; }
    echo CASE_DURABLE_STORAGE_FULL_PASS
fi
echo "QEMU_POWERLOSS_PASS_PHASE_$phase"
trap - EXIT
poweroff -f
