"""@file qemu_native_launch.py
@brief Replay the original Unitree SDK adapter through the production CLI in QEMU.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET

from qemu_supervisor import digest, pack
from vendor_qualification import cgroup
from vendor_unitree_qemu import sign_attachment


def stage_fixture(archive, root):
    """@brief Reuse the hash-pinned dependencies from the preceding vendor replay."""
    with gzip.open(archive) as stream:
        while True:
            header = stream.read(110)
            if len(header) != 110 or header[:6] != b"070701":
                raise ValueError("invalid newc vendor initramfs")
            fields = [int(header[6 + 8*i:14 + 8*i], 16) for i in range(13)]
            mode, size, length = fields[1], fields[6], fields[11]
            if not 1 <= length <= 4096:
                raise ValueError("invalid newc member size")
            name = stream.read(length).rstrip(b"\0").decode()
            stream.read((-110-length) % 4)
            if name == "TRAILER!!!":
                break
            relative = PurePosixPath(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("unsafe newc member path")
            selected = (
                relative.parts and relative.parts[0] in ("lib", "lib64", "usr")
                or name.startswith("opt/unitree/")
                or name in ("bin/busybox", "bin/low-state", "etc/passwd", "etc/group", "bundle/unitree-provider")
            )
            if selected and stat.S_ISREG(mode):
                path = root / relative
                path.parent.mkdir(exist_ok=True, parents=True)
                with path.open("xb") as dest:
                    pending = size
                    while pending:
                        data = stream.read(min(pending, 1 << 20))
                        if not data:
                            raise ValueError("truncated newc member")
                        dest.write(data)
                        pending -= len(data)
                path.chmod(stat.S_IMODE(mode))
                stream.read((-size) % 4)
            else:
                if selected and not stat.S_ISDIR(mode):
                    raise ValueError("unexpected dependency fixture file type")
                stream.seek(size + (-size) % 4, os.SEEK_CUR)


def prepare_deployment(args, root, original):
    """@brief Generate signatures, matching review documents, and controlled negative inputs."""
    bundle = root / "bundle"
    driver = bundle / "unitree-provider"
    prior = original["secure_attachment"]
    marker = b"~Module signature appended~\n"
    prior_signed = driver.read_bytes()
    if digest(driver) != prior["signed_native_provider_sha256"] or not prior_signed.endswith(marker):
        raise ValueError("unexpected signed provider in prior initramfs")
    length = int.from_bytes(prior_signed[-len(marker)-4:-len(marker)], "big")
    payload = prior_signed[:-(length + 12 + len(marker))]
    if hashlib.sha256(payload).hexdigest() != prior["native_provider_sha256"]:
        raise ValueError("prior signed provider does not contain the reviewed ELF")
    driver.write_bytes(payload)
    sign_attachment(args, root, args.module)
    (bundle / "unsigned").write_bytes(payload)
    modified = bytearray(driver.read_bytes())
    modified[len(payload) - 1] ^= 1
    (bundle / "invalid").write_bytes(modified)
    rights = ET.Element("recommendations")
    for name in ("capability.open", "driver.connect", "driver.submit", "driver.result", "driver.disconnect"):
        ET.SubElement(rights, "interface", name=name, expose="allow")
    ET.ElementTree(rights).write(bundle / "denied.xml")
    ET.SubElement(rights, "driver-resource", alias="go2-state", operation="buffer.read", access="allow")
    ET.ElementTree(rights).write(bundle / "rights.xml")
    contract = Path(__file__).with_name("support") / "unitree_low_state_contract.txt"
    for label, provider in (("signed", driver), ("signed-int", driver), ("unsigned", bundle / "unsigned"),
                            ("invalid", bundle / "invalid"), ("permission-denied", driver)):
        deployment = ET.Element("deployment", id="unitree")
        ET.SubElement(deployment, "vm", id="main", module="controller.wasm", policy="admission.policy",
                      engine="interpreter" if label == "signed-int" else "aot",
                      uid="24101", gid="24101", sha256=digest(bundle / "controller.wasm"), pids="16",
                      recommendations="denied.xml" if label == "permission-denied" else "rights.xml",
                      **{"vm-policy": "vm.policy", "memory-bytes": "536870912"})
        node = ET.SubElement(deployment, "driver", id="unitree", file=provider.name, kind="executable",
                             sha256=digest(provider), **{"vendor-version": "2.0.2",
                             "hardware-id": "go2-low-state", "elf-signer": "wasm-signer.pem"})
        ET.SubElement(node, "attachment", vm="main", alias="go2-state", sandbox="go2",
                      uid="24102", gid="24102", pids="32", **{"contract-sha256": digest(contract),
                      "memory-bytes": "268435456", "cpu-micros": "100000", "request-millis": "180000"})
        ET.ElementTree(deployment).write(bundle / (label + ".xml"))
        (bundle / (label + ".sha")).write_text(digest(provider) + "\n")
    return contract


def prepare_edge_cases(root):
    """@brief Set up deterministic trust and source changes during initial admission."""
    bundle = root / "bundle"
    (root / "sandboxes/go2/proc").mkdir(exist_ok=True)
    # The original SDK resolves its effective UID through the sandbox's NSS.
    etc = root / "sandboxes/go2/etc"
    for name, value in (("passwd", "provider:x:24102:24102:Go2 telemetry:/:/bin/false\n"),
                        ("group", "provider:x:24102:\n")):
        path = etc / name
        path.unlink(missing_ok=True)
        path.write_text(value)
        path.chmod(0o644)
    for case, key, value in (("signer-withdrawn", "elf-signer", "launch-only.pem"),
                              ("sealed-replacement", "file", "swap-provider")):
        xml = ET.parse(bundle / "signed.xml")
        xml.getroot().find("driver").set(key, value)
        xml.write(bundle / (case + ".xml"))
    shutil.copyfile(root / "trust/wasm-signer.pem", root / "trust/launch-only.pem")
    (root / "trust/launch-only.pem").chmod(0o644)
    (bundle / "swap-provider").unlink(missing_ok=True)
    os.link(bundle / "unitree-provider", bundle / "swap-provider")
    (bundle / "replacement").write_bytes(b"source name no longer refers to the admitted ELF")
    helper = Path(__file__).with_name("support") / "native_launch_verifier.c"
    subprocess.run(["/usr/bin/cc", "-static", "-O3", "-g", "-Wall", "-Wextra", "-Werror",
                    helper, "-o", root / "bin/test-elf-verifier"], check=True, timeout=45)
    (root / "bin/test-elf-verifier").chmod(0o755)
    return helper


def main():
    """@brief Verify source lineage, boot the kernel, and retain exact test outcomes."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "base", "base-receipt", "module", "vm", "vm-source",
                 "deployer", "cosign", "sign-file", "signing-scratch", "kernel", "bios",
                 "firmware-directory"):
        parser.add_argument("--" + name, type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--qemu", type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    group = cgroup()
    if any(".tmp" not in path.parts for path in (args.output, args.base, args.signing_scratch)):
        parser.error("fixtures and output must be under repository .tmp")
    original = json.loads(args.base_receipt.read_bytes())
    if not original.get("complete") or original["initramfs_sha256"] != digest(args.base):
        raise ValueError("vendor inputs differ from the prior qualified artifacts")
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    for key in ("TMPDIR", "TMP", "TEMP"):
        os.environ[key] = str(args.output)
    root = args.output / "root"
    for name in ("bin", "etc", "dev", "proc", "sys", "run", "tmp", "trust", "bundle", "sandboxes/go2"):
        (root / name).mkdir(parents=True, exist_ok=True)
    stage_fixture(args.base, root)
    (root / "bin/sh").symlink_to("busybox")
    # The packer writes fresh regular inodes in the guest for these hard links.
    for name, path in (("uwvm2-ros", args.vm), ("cosign", args.cosign)):
        if path.stat().st_mode & 0o022:
            raise ValueError("verifier input needs protected file permissions")
        os.link(path, root / "bin" / name)
    subprocess.run(["/usr/bin/objcopy", "--strip-debug", args.deployer, root / "bin/wros-deployer"],
                   check=True, timeout=45)
    (root / "bin/wros-deployer").chmod(0o755)
    sandbox = root / "sandboxes/go2"
    for folder in ("lib", "lib64", "usr", "opt", "etc"):
        if (root / folder).is_dir():
            shutil.copytree(root / folder, sandbox / folder, copy_function=os.link)
    contract = prepare_deployment(args, root, original)
    helper = prepare_edge_cases(root)
    entry = Path(__file__).with_name("qemu_native_launch_guest.sh")
    shutil.copyfile(entry, root / "init")
    (root / "init").chmod(0o755)
    initrd = args.output / "initramfs.cpio.gz"
    pack(root, initrd)
    argv = [args.qemu, "-nodefaults", "-machine", "q35", "-accel", "kvm", "-cpu", "host",
            "-smp", "2", "-m", "2048", "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-nic", "none", "-no-reboot", "-bios", args.bios, "-L", args.firmware_directory,
            "-kernel", args.kernel, "-initrd", initrd,
            "-append", "console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all"]
    inputs = [args.base_receipt, args.module, args.vm, args.cosign, args.sign_file,
              args.deployer, args.kernel, entry, contract, helper]
    receipt = {"inputs": {str(path): digest(path) for path in inputs},
               "deployment_binary_sha256": digest(root / "bin/wros-deployer"),
               "initramfs_sha256": digest(initrd), "cgroup": str(group), "argv": list(map(str, argv))}
    serial = args.output / "serial.log"
    with serial.open("wb") as log:
        result = subprocess.run(list(map(str, argv)), stdout=log, stderr=subprocess.STDOUT, timeout=110)
    transcript = serial.read_text(errors="replace")
    receipt["cases"] = re.findall(r"^CASE ([-a-z]+) PASS$", transcript, re.MULTILINE)
    expected = {"rejects-unsigned-by-default", "rejects-invalid-by-default",
                "rejects-wrong-exception-id", "rejects-wrong-exception-digest",
                "rejects-wrong-exception-kind", "requires-per-driver-permission",
                "withdrawn-signer-denied-before-exec", "production-signed",
                "production-signed-int", "production-unsigned", "production-invalid",
                "production-sealed-replacement"}
    receipt["complete"] = (result.returncode == 0 and "WROS_NATIVE_LAUNCH_PASS" in transcript
                           and set(receipt["cases"]) == expected and len(receipt["cases"]) == len(expected))
    receipt["serial_sha256"] = digest(serial)
    (args.output / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if not receipt["complete"]:
        raise SystemExit(transcript[-5000:])
    print("Production native ELF launch verified.")


if __name__ == "__main__":
    main()
