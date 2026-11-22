#!/usr/bin/env python3
"""@file vendor_unitree_qemu.py
@brief Run signed native Unitree DDS telemetry tests in an offline QEMU guest.
"""

import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

from qemu_supervisor import digest, pack
from vendor_qualification import cgroup


REVISION = "811bc77cdcffb4691d4b40172f9a57857bf6cffb"
ARCHIVE_SHA256 = "5e0fe1936221ba37299cc037abe0fd9c8c878e623ddb900d4584a7cd9c865120"
GUEST_CASES = {
    "native-signature",
    "altered-manifest-denied",
    "unitree-official-hello-world",
    "unitree-go2-low-state",
}
ATTACHMENT_CASES = {
    "unitree-wsea-admission",
    "unitree-modified-wasm-denied",
    "unitree-go2-attachment-int",
    "unitree-go2-attachment-aot",
    "unitree-attachment-authentication-denied",
}
GUEST_INIT = """#!/bin/sh
set -eu
export PATH=/bin
finish() { poweroff -f; }
trap finish EXIT
busybox mount -t proc proc /proc
busybox mount -t sysfs sysfs /sys
busybox mount -t devtmpfs devtmpfs /dev
busybox mount -t cgroup2 cgroup2 /sys/fs/cgroup
test "$(busybox ls /sys/class/net)" = lo
busybox ip link set lo multicast on up

cd /
openssl pkeyutl -verify -rawin -pubin -inkey /trust/native.pub \\
    -in /trust/native.sha256 -sigfile /trust/native.sig
busybox sha256sum -c /trust/native.sha256
echo 'CASE native-signature PASS'
busybox cp /trust/native.sha256 /run/altered
echo altered >> /run/altered
if openssl pkeyutl -verify -rawin -pubin -inkey /trust/native.pub \\
    -in /run/altered -sigfile /trust/native.sig; then
    exit 1
fi
echo 'CASE altered-manifest-denied PASS'

group=/sys/fs/cgroup
busybox mkdir "$group"/supervisor
echo $$ > "$group"/supervisor/cgroup.procs
echo '+memory +pids' > "$group"/cgroup.subtree_control
echo 134217728 > "$group"/supervisor/memory.max
echo 0 > "$group"/supervisor/memory.swap.max
for role in reader writer; do
    busybox mkdir "$group/$role"
    echo 134217728 > "$group/$role/memory.max"
    echo 0 > "$group/$role/memory.swap.max"
    echo 32 > "$group/$role/pids.max"
done
cd "$group"
(
    echo 0 > writer/cgroup.procs
    exec busybox su -s /bin/sh -c 'LD_LIBRARY_PATH=/opt/unitree exec /bin/test_publisher' writer
) > /run/hello-writer.log 2>&1 &
writer=$!
(
    echo 0 > reader/cgroup.procs
    exec busybox su -s /bin/sh -c 'LD_LIBRARY_PATH=/opt/unitree exec /bin/test_subscriber' reader
) > /run/hello-reader.log 2>&1 &
reader=$!
busybox sleep 5
test "$(busybox cat writer/cgroup.events | busybox head -1)" = 'populated 1'
test "$(busybox cat reader/cgroup.events | busybox head -1)" = 'populated 1'
echo 1 > writer/cgroup.kill
echo 1 > reader/cgroup.kill
wait "$writer" || :
wait "$reader" || :
busybox cat /run/hello-writer.log /run/hello-reader.log
busybox grep -Eq '^userID:[0-9]+, message:HelloWorld[.]$' /run/hello-reader.log
echo 'CASE unitree-official-hello-world PASS'

(
    echo 0 > writer/cgroup.procs
    exec busybox su -s /bin/sh -c 'LD_LIBRARY_PATH=/opt/unitree exec /bin/low-state publish' writer
) > /run/state-writer.log 2>&1 &
writer=$!
(
    echo 0 > reader/cgroup.procs
    exec busybox su -s /bin/sh -c 'LD_LIBRARY_PATH=/opt/unitree exec /bin/low-state read' reader
) > /run/state-reader.log 2>&1 &
reader=$!
reader_status=0
writer_status=0
wait "$reader" || reader_status=$?
wait "$writer" || writer_status=$?
busybox cat /run/state-reader.log /run/state-writer.log
test "$reader_status" -eq 0
test "$writer_status" -eq 0
busybox grep -Fx 'Go2 LowState tick=41347 position=0.125' /run/state-reader.log
for role in reader writer; do
    test "$(busybox cat "$role/cgroup.events" | busybox head -1)" = 'populated 0'
    busybox grep -Fx 'oom 0' "$role/memory.events"
    busybox grep -Fx 'oom_kill 0' "$role/memory.events"
    busybox rmdir "$role"
done
echo 'CASE unitree-go2-low-state PASS'
"""


def run(argv, **kwargs):
    """@brief Execute one bounded preparation command."""
    return subprocess.run(list(map(str, argv)), check=True, timeout=120, **kwargs)


def stage_binary(root, source, name, library_dir=None):
    """@brief Copy a test executable and its exact runtime libraries."""
    executable = root / "bin" / name
    shutil.copyfile(source, executable)
    executable.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin"}
    if library_dir is not None:
        env["LD_LIBRARY_PATH"] = str(library_dir)
    probe = subprocess.run(["/usr/bin/ldd", source], env=env, capture_output=True,
                           text=True, timeout=120)
    output = probe.stdout + probe.stderr
    if probe.returncode and "not a dynamic executable" not in output:
        raise ValueError(f"ldd failed for {source}: {output}")
    if "not found" in output:
        raise ValueError(f"missing runtime dependency for {source}")
    for path in re.findall(r"(?:=>\s*)?(/[^\s]+)\s+\(", output):
        library = Path(path)
        destination = (Path("opt/unitree") / library.name
                       if library.parent == library_dir else library.relative_to("/"))
        target = root / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(library, target)


def build_vendor(archive, output, root):
    """@brief Build the unchanged upstream samples and the Go2 read-only fixture."""
    source = output / "unitree"
    source.mkdir()
    with tarfile.open(archive, "r:gz") as package:
        package.extractall(source, filter="data")
    sdk = source / ("unitree_sdk2-" + REVISION)
    fixture = Path(__file__).with_name("support") / "unitree_low_state.cpp"
    examples = sdk / "example/helloworld"
    libraries = sdk / "thirdparty/lib/x86_64"
    inputs = {
        "hello publisher": [examples / "publisher.cpp", examples / "HelloWorldData.cpp"],
        "hello subscriber": [examples / "subscriber.cpp", examples / "HelloWorldData.cpp"],
        "Go2 telemetry": [fixture],
    }
    names = ("test_publisher", "test_subscriber", "low-state")
    with (output / "build.log").open("wb") as transcript:
        for sources, name in zip(inputs.values(), names, strict=True):
            executable = output / name
            run(["/usr/bin/g++", "-std=c++17", "-O3", "-g", "-pthread",
                 "-I", sdk / "include", "-isystem", sdk / "thirdparty/include",
                 "-isystem", sdk / "thirdparty/include/ddscxx", *sources,
                 sdk / "lib/x86_64/libunitree_sdk2.a", "-L", libraries,
                 "-lddscxx", "-lddsc", "-o", executable],
                stdout=transcript, stderr=subprocess.STDOUT)
            stage_binary(root, executable, name, libraries)
    inputs["vendor libraries"] = [sdk / "lib/x86_64/libunitree_sdk2.a",
                                   libraries / "libddsc.so", libraries / "libddscxx.so"]
    return {str(path): digest(path) for files in inputs.values() for path in files}


def sign(root, output):
    """@brief Sign the native byte inventory with a disposable Ed25519 key."""
    trust = root / "trust"
    manifest = trust / "native.sha256"
    signed_files = tuple(path for path in sorted(root.rglob("*")) if path.is_file())
    manifest.write_text("".join(f"{digest(path)}  /{path.relative_to(root)}\n" for path in signed_files))
    openssl = "/usr/bin/openssl"
    with tempfile.TemporaryDirectory(dir=output) as scratch:
        key = Path(scratch) / "test.key"
        run([openssl, "genpkey", "-algorithm", "ED25519", "-out", key])
        run([openssl, "pkey", "-in", key, "-pubout", "-out", trust / "native.pub"])
        run([openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", manifest,
             "-out", trust / "native.sig"])
    return {path.name: digest(path) for path in trust.iterdir()}


def sign_attachment(args, root, wasm):
    """@brief Sign the Wasm and ELF with one disposable P-384 key."""
    fixtures = args.vm_source / "test/0073.ros-tests/support/source/security_wsea/algorithm_matrix.py"
    spec = importlib.util.spec_from_file_location("fixture_signer", fixtures)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    with tempfile.TemporaryDirectory(dir=args.signing_scratch) as directory:
        scratch = Path(directory)
        authority = fixture.Fixtures(scratch / "authority").pki("unitree", curve="secp384r1")
        policy = scratch / "sign.policy"
        state = scratch / "state"
        state.mkdir(mode=0o700)
        unsigned = scratch / "unsigned.wasm"
        shutil.copyfile(wasm, unsigned)
        prefix = [args.cosign, "wasm", "secure"]
        run([*prefix, "policy-init", "--output", policy, "--state-dir", state,
             "--trust-root", authority["root"], "--certificate", authority["certificate"],
             "--module-id", "main", "--algorithms", "ES384", "--capabilities", "32"])
        now = datetime.now(timezone.utc)
        before = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        after = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        signed = scratch / "signed.wasm"
        run([*prefix, "sign", unsigned, "--policy", policy, "--key", authority["key"],
             "--certificate", authority["certificate"], "--crl", authority["crl"],
             "--module-id", "main", "--module-version", "1", "--algorithm", "ES384",
             "--capabilities", "32", "--not-before", before, "--not-after", after,
             "--output", signed])
        for source, target in ((authority["root"], "trust/wasm-root.pem"),
                               (authority["certificate"], "trust/wasm-signer.pem"),
                               (signed, "bundle/controller.wasm")):
            shutil.copyfile(source, root / target)
            (root / target).chmod(0o644)
        signed_elf = scratch / "unitree-provider"
        run([args.sign_file, "sha384", authority["key"], authority["certificate"],
             root / "bundle/unitree-provider", signed_elf])
        shutil.copyfile(signed_elf, root / "bundle/unitree-provider")


def compile_attachment(args, sdk, binary, extra_flags=()):
    """@brief Build the telemetry adapter against the selected original SDK and static TLS libraries."""
    support = Path(__file__).with_name("support")
    source = [support / "unitree_low_state.cpp", support / "unitree_attachment.cpp"]
    libraries = sdk / "thirdparty/lib/x86_64"
    ssl = args.openssl_root
    ssl_inputs = [ssl / "libssl.a", ssl / "libcrypto.a"]
    compile_provider = [
        "/usr/bin/clang++-22", "-std=c++23", "-O3", "-g", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-DWROS_UNITREE_ATTACHMENT", "-DUWVM_ROS_ATTACHMENT_OPENSSL", *extra_flags,
        "-I", args.vm_source / "src", "-isystem", args.vm_source / "third-parties/fast_io/include",
        "-isystem", ssl / "include", "-isystem", sdk / "include",
        "-isystem", sdk / "thirdparty/include", "-isystem", sdk / "thirdparty/include/ddscxx",
        *source, sdk / "lib/x86_64/libunitree_sdk2.a", *ssl_inputs, "-L", libraries,
        "-lddscxx", "-lddsc", "-ldl", "-Wl,-rpath,/opt/unitree", "-o", binary,
    ]
    with (args.output / "attachment-build.log").open("wb") as log:
        run(compile_provider, stdout=log, stderr=subprocess.STDOUT)
    return compile_provider, source, ssl_inputs


def build_attachment(args, root):
    """@brief Stage the original SDK, its read-only adapter and the signed Wasm guest."""
    tests = Path(__file__).resolve().parent
    support = tests / "support"
    out = args.output
    sdk = out / "unitree" / ("unitree_sdk2-" + REVISION)
    libraries = sdk / "thirdparty/lib/x86_64"
    binary = out / "unitree-provider"
    compile_provider, source, ssl_inputs = compile_attachment(args, sdk, binary)
    stage_binary(root, binary, "unitree-provider", libraries)
    for executable, filename in ((args.vm, "uwvm2-ros"), (args.cosign, "cosign"),
                                 (args.deployer, "wros-deployer"), (args.provisioner, "provisioner")):
        stage_binary(root, executable, filename)

    bundle = root / "bundle"
    bundle.mkdir()
    (root / "bin/unitree-provider").rename(bundle / "unitree-provider")
    wasm = out / "controller.wasm"
    wat = support / "unitree_low_state.wat"
    assembler = args.wrwat
    build_wasm = [assembler, wat, "-g", "--build-receipt", "-o", wasm]
    for operation in ("capability.open", "driver.connect", "driver.submit", "driver.result", "driver.disconnect"):
        build_wasm.extend(("--ros-operation", operation))
    run(build_wasm)
    sign_attachment(args, root, wasm)
    controller = bundle / "controller.wasm"
    data = controller.read_bytes()
    if data.count(b"go2-state") != 1:
        raise ValueError("cannot construct the expected Wasm integrity refusal")
    tampered = bundle / "changed.wasm"
    tampered.write_bytes(data.replace(b"go2-state", b"go2-statf"))
    for module, filename in ((controller, "deployment.xml"), (tampered, "changed.xml")):
        manifest = ET.Element("deployment", id="unitree-read-only")
        ET.SubElement(manifest, "vm", id="main", module=module.name, policy="admission.policy",
                      sha256=digest(module), **{"memory-bytes": "536870912", "pids": "16"})
        ET.SubElement(manifest, "driver", id="unitree", file="unitree-provider", kind="executable",
                      sha256=digest(bundle / "unitree-provider"),
                      **{"vendor-version": "2.0.2", "hardware-id": "offline-go2", "elf-signer": "wasm-signer.pem"})
        ET.ElementTree(manifest).write(bundle / filename)

    guest = tests / "vendor_unitree_attachment_guest.sh"
    shutil.copyfile(guest, root / "run/attachment-test.sh")
    inputs = [*source, wat, support / "unitree_low_state_contract.txt", guest, *ssl_inputs,
              args.vm, args.cosign, args.deployer, args.provisioner, args.sign_file, assembler]
    return {
        "inputs": {str(path): digest(path) for path in inputs},
        "compile_provider": list(map(str, compile_provider)),
        "assemble_guest": list(map(str, build_wasm)),
        "guest_build_receipt": json.loads(wasm.with_suffix(".wasm.wros-wat.json").read_text()),
        "signed_wasm_sha256": digest(controller),
        "native_provider_sha256": digest(binary),
        "signed_native_provider_sha256": digest(bundle / "unitree-provider"),
    }


def main():
    """@brief Build and verify the isolated driver replay."""
    cli = argparse.ArgumentParser(description=__doc__)
    for option in ("archive", "kernel", "bios", "firmware-directory", "output"):
        cli.add_argument("--" + option, type=lambda path: Path(path).resolve(), required=True)
    # Keep the name used by launchers that dispatch on argv[0].
    cli.add_argument("--qemu", type=lambda path: Path(path).absolute(), required=True)
    cli.add_argument("--accelerator", choices=("tcg", "kvm"), default="tcg")
    attachment_options = ("vm", "vm-source", "openssl-root", "deployer", "provisioner",
                          "wrwat", "cosign", "sign-file", "signing-scratch")
    for option in attachment_options:
        cli.add_argument("--" + option, type=lambda path: Path(path).resolve(strict=True))
    args = cli.parse_args()
    selected = [getattr(args, name.replace("-", "_")) is not None for name in attachment_options]
    if any(selected) and not all(selected):
        cli.error("the authenticated attachment replay requires all VM, SDK, deployer and signing inputs")
    attachment = all(selected)
    group = cgroup()
    if ".tmp" not in args.output.parts:
        cli.error("choose a fresh output within .tmp")
    if attachment and (".tmp" not in args.signing_scratch.parts
                       or args.signing_scratch.stat().st_uid != os.geteuid()
                       or args.signing_scratch.stat().st_mode & 0o077):
        cli.error("choose a private signing scratch directory owned by the current user under .tmp")
    if digest(args.archive) != ARCHIVE_SHA256:
        cli.error("the SDK archive differs from the pinned upstream bytes")
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    for variable in ("TMPDIR", "TMP", "TEMP"):
        os.environ[variable] = str(args.output)
    root = args.output / "root"
    for folder in ("bin", "dev", "proc", "sys", "run", "etc", "trust"):
        (root / folder).mkdir(parents=True)
    (root / "etc/passwd").write_text(
        "root:x:0:0:root:/:/bin/sh\n"
        "reader:x:24001:24001:reader:/:/bin/sh\n"
        "writer:x:24002:24002:writer:/:/bin/sh\n"
        "telemetry:x:24003:24003:telemetry:/:/bin/sh\n")
    (root / "etc/group").write_text("root:x:0:\nreader:x:24001:\nwriter:x:24002:\ntelemetry:x:24003:\n")
    for name in ("passwd", "group"):
        (root / "etc" / name).chmod(0o644)
    stage_binary(root, Path("/bin/busybox"), "busybox")
    stage_binary(root, Path("/usr/bin/openssl"), "openssl")
    (root / "bin/sh").symlink_to("busybox")
    vendor_inputs = build_vendor(args.archive, args.output, root)
    attachment_inputs = build_attachment(args, root) if attachment else None
    init = GUEST_INIT
    if attachment:
        init += "\n/bin/sh /run/attachment-test.sh\n"
    (root / "init").write_text(init + "\necho WROS_UNITREE_PASS\n")
    (root / "init").chmod(0o755)
    native_signature = sign(root, args.output)
    initramfs = args.output / "initramfs.cpio.gz"
    pack(root, initramfs)
    cpu = ["-accel", "kvm", "-cpu", "host"] if args.accelerator == "kvm" else [
        "-accel", "tcg,thread=multi", "-cpu", "max"]
    argv = [args.qemu, "-nodefaults", "-machine", "q35", *cpu,
            "-smp", "2", "-m", "2048" if attachment else "768",
            "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-nic", "none", "-no-reboot", "-bios", args.bios, "-L", args.firmware_directory,
            "-kernel", args.kernel, "-initrd", initramfs,
            "-append", "console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all"]
    record = {
        "complete": False, "vendor": "Unitree", "release": "2.0.2", "revision": REVISION,
        "archive_sha256": ARCHIVE_SHA256, "cgroup": str(group),
        "upstream_and_fixture_inputs": vendor_inputs, "native_signature": native_signature,
        "secure_attachment": attachment_inputs,
        "kernel_sha256": digest(args.kernel), "initramfs_sha256": digest(initramfs),
        "argv": list(map(str, argv)), "host_memory_events_before": (group / "memory.events").read_text(),
    }
    receipt = args.output / "results.json"
    receipt.write_text(json.dumps(record, indent=2) + "\n")
    serial = args.output / "serial.log"
    with serial.open("wb") as log:
        result = subprocess.run(list(map(str, argv)), stdout=log, stderr=subprocess.STDOUT, timeout=110)
    transcript = serial.read_text(errors="replace")
    cases = re.findall(r"^CASE (\S+) PASS$", transcript, re.MULTILINE)
    record.update(cases=cases, exit=result.returncode, serial_sha256=digest(serial),
                  host_memory_events_after=(group / "memory.events").read_text())
    expected = GUEST_CASES | ATTACHMENT_CASES if attachment else GUEST_CASES
    record["complete"] = (result.returncode == 0 and "WROS_UNITREE_PASS" in transcript
                          and set(cases) == expected and len(cases) == len(expected))
    receipt.write_text(json.dumps(record, indent=2) + "\n")
    if not record["complete"]:
        raise SystemExit(transcript[-3000:])
    print("Unitree signed native DDS replay passed.")


if __name__ == "__main__":
    main()
