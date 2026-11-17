#!/bin/sh
# PID 1 bootstrap of the disposable test guest, never a host installation script.
set -eu
export PATH=/bin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mkdir -p /sys/fs/cgroup /scratch /state/admission /state/body /dev/pts
mount -t devpts devpts /dev/pts
mount -t cgroup2 none /sys/fs/cgroup
chmod 700 /scratch /state/admission /state/body
/bin/cosign wasm secure policy-init --output /trust/body.policy --state-dir /state/admission --trust-root /trust/root.pem --certificate /trust/signer.pem --module-id body --algorithms Ed25519
/bin/cosign wasm secure policy-init --output /trust/body-vm.policy --state-dir /state/body --trust-root /trust/root.pem --certificate /trust/signer.pem --module-id body --algorithms Ed25519
chmod 644 /trust/body.policy /trust/body-vm.policy
chown -R 10001:10001 /state/body
exec /usr/lib/systemd/systemd --system --unit=wros-test.target --log-target=console --log-level=warning
