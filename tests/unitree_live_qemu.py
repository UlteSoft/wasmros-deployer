#!/usr/bin/env python3
"""@file unitree_live_qemu.py
@brief Boot signed Go2 simulation and Wasm clients with the production deployer in offline KVM.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from qemu_supervisor import build_review_terminal, digest, pack
from unitree_live_build import MUJOCO_LIBRARY, MUJOCO_SHA256, PROFILES, SUPPORT, inventory, paths, strict_receipt
from vendor_qualification import qualification_environment
from vendor_unitree_mujoco import PINNED_INPUTS, require_digest
from vendor_unitree_qemu import CLOCK_INTERFACES, certificate_authority, run, sign_controller, stage_binary, stage_libraries


def copy_file(source, target, mode=0o444):
    """@brief Copy a regular file into the guest with a protected mode."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def check_build(build, p):
    """@brief Check original build inputs and both distinct outputs before local signing."""
    row = json.loads((build / "build.json").read_bytes())
    app, native = row["application"], row["provider"]
    require_digest(build / "controller.wasm", app["sha256"])
    require_digest(build / "unitree-provider", native["sha256"])
    for inputs in (app["inputs"], native["inputs"]):
        for name, expected in inputs.items():
            require_digest(Path(name), expected)
    if app["kind"] in ("signed-wrcc", "ros-angles"):
        receipt = (p["wrcc_receipt"] if app["kind"] == "signed-wrcc"
                   else build / "controller.wasm.wros-build.json")
        if strict_receipt(receipt, build / "controller.wasm", p["vm"]) != app["receipt"]:
            raise ValueError("WrCC build metadata changed after compilation")
    elif app["kind"] != "live-wat":
        raise ValueError("unknown Wasm client")
    return app


def stage_root(p, build, root):
    """@brief Stage the exact model and runtime library closure inside the protected provider root."""
    for directory in ("bin", "dev", "etc", "proc", "run", "sys", "tmp", "trust", "bundle", "sandboxes/go2/proc"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for path, filename in ((Path("/bin/busybox"), "busybox"), (p["vm"], "uwvm2-ros"),
                           (p["cosign"], "cosign"), (p["deployer"], "wros-deployer")):
        stage_binary(root, path, filename)
    (root / "bin/sh").symlink_to("busybox")
    review_source = build_review_terminal(root)
    guest = SUPPORT.parent / "unitree_live_guest.sh"
    copy_file(guest, root / "init", 0o555)
    sandbox = root / "sandboxes/go2"
    sdk_lib = p["sdk"] / "thirdparty/lib/x86_64"
    for versioned, expected in (("libddsc.so.0", PINNED_INPUTS["libddsc.so"]),
                                ("libddscxx.so.0", PINNED_INPUTS["libddscxx.so"])):
        require_digest(sdk_lib / versioned, expected)
    require_digest(p["mujoco"] / MUJOCO_LIBRARY, MUJOCO_SHA256)
    libraries = stage_libraries(sandbox, build / "unitree-provider", (sdk_lib, p["mujoco"]))
    for lib in libraries:
        lib.chmod(0o555)
    for filename, data in (("passwd", "root:x:0:0:root:/:/bin/sh\nvm:x:24101:24101:VM:/:/bin/false\n"
                             "provider:x:24102:24102:Go2:/:/bin/false\n"),
                           ("group", "root:x:0:\nvm:x:24101:\nprovider:x:24102:\n"),
                           ("nsswitch.conf", "passwd: files\ngroup: files\n")):
        target = root / "etc" / filename
        target.write_text(data)
        target.chmod(0o444)
        copy_file(target, sandbox / "etc" / filename)
    provenance = p["model"] / "provenance.json"
    require_digest(provenance, PINNED_INPUTS["provenance.json"])
    models = json.loads(provenance.read_bytes())["files"]
    for filename, expected in models.items():
        source = p["model"] / filename
        require_digest(source, expected)
        copy_file(source, sandbox / "simulator" / filename)
    return {"model": models, "solver_libraries": {str(path.relative_to(sandbox)): digest(path) for path in libraries},
            "supervisor_inputs": inventory([guest, review_source, p["vm"], p["cosign"], p["deployer"], p["sign_file"]])}


def sign_inputs(p, build, root, app, scratch):
    """@brief Issue independent identities for the module and the native provider."""
    inputs = root.parent / "signed-inputs"
    inputs.mkdir()
    driver = inputs / "unitree-provider"
    native = certificate_authority(p["vm_source"], scratch / "driver-authority", "go2-provider")
    run([p["sign_file"], "sha384", native["key"], native["certificate"], build / "unitree-provider", driver])
    driver.chmod(0o555)
    copy_file(native["certificate"], root / "trust/driver-signer.pem")
    module = inputs / "controller.wasm"
    if app["kind"] == "signed-wrcc":
        copy_file(p["signed_app"], module)
        ca, cert = p["app_root"], p["app_signer"]
    else:
        authority = certificate_authority(p["vm_source"], scratch / "wasm-authority", "go2-application")
        sealed_module = scratch / "signed.wasm"
        sign_controller(p["cosign"], scratch, authority, build / "controller.wasm", sealed_module)
        copy_file(sealed_module, module)
        ca, cert = authority["root"], authority["certificate"]
    copy_file(ca, root / "trust/app-root.pem")
    copy_file(cert, root / "trust/app-signer.pem")
    if app["kind"] == "signed-wrcc":
        for path, key in ((module, "signed_app"), (root / "trust/app-root.pem", "app_root"),
                          (root / "trust/app-signer.pem", "app_signer")):
            require_digest(path, app["external"][key])
    module.chmod(0o444)
    return inputs, {"application": {"unsigned": app["sha256"], "signed": digest(module),
                                    "root": digest(ca), "signer": digest(cert), "kind": app["kind"]},
                    "driver": {"unsigned": digest(build / "unitree-provider"), "signed": digest(driver),
                               "signer": digest(native["certificate"])}, "contract": digest(SUPPORT / "unitree_live_contract.txt")}


def write_xml(path, document):
    """@brief Serialize a deterministic UTF-8 deployment or recommendations document."""
    ET.indent(document)
    ET.ElementTree(document).write(path, encoding="utf-8", xml_declaration=True)
    path.chmod(0o444)


def deployment(p, root, inputs, profile, module, engine):
    """@brief Use the installed SDK driver generator and preserve individually reviewed clock permissions."""
    bundle = root / "bundle" / profile
    bundle.mkdir()
    request, response = PROFILES[profile]
    for name in ("controller.wasm", "unitree-provider"):
        os.link(inputs / name, bundle / name)
    os.link(root / "trust/driver-signer.pem", bundle / "driver-signer.pem")
    contract = bundle / "go2-mujoco.contract"
    copy_file(SUPPORT / "unitree_live_contract.txt", contract)
    command = [sys.executable, "-I", "-B", p["driver_config"], "--platform", "unitree", "--vm", module,
               "--driver-id", "unitree", "--vendor-version", "2.0.2", "--hardware-id", "go2-mujoco-low-state",
               "--alias", "go2-state", "--contract", contract.name, "--elf", "unitree-provider",
               "--elf-signer", "driver-signer.pem", "--sandbox", "go2", "--uid", "24102",
               "--request-bytes", str(request), "--response-bytes", str(response), "--bundle", bundle]
    run(command)
    fragment = bundle / "driver-unitree/deployment.xml"
    driver = ET.parse(fragment).getroot().find("driver")
    attachment = driver.find("attachment")
    if (driver.get("sha256") != digest(inputs / "unitree-provider") or attachment.get("contract-sha256") != digest(contract)
            or tuple(attachment.get(key) for key in ("vm", "uid", "gid", "request-bytes", "response-bytes", "request-millis"))
            != (module, "24102", "24102", str(request), str(response), "2000")):
        raise ValueError("SDK driver fragment differs from the live contract")
    xml = ET.Element("deployment", id="unitree")
    ET.SubElement(xml, "vm", id=module, module="controller.wasm", policy="admission.policy",
                  engine=engine, uid="24101", gid="24101", sha256=digest(inputs / "controller.wasm"),
                  pids="16", recommendations="rights.xml", **{"vm-policy": "vm.policy", "memory-bytes": "536870912"})
    ET.SubElement(xml, "include", file="driver-unitree/deployment.xml")
    write_xml(bundle / "deployment.xml", xml)
    rights = ET.Element("recommendations")
    ET.SubElement(rights, "include", file="driver-unitree/recommendations.xml")
    for operation in CLOCK_INTERFACES:
        ET.SubElement(rights, "interface", name=operation, expose="allow")
        ET.SubElement(rights, "local-resource", type="clock.steady", alias="steady", operation=operation, access="allow")
    write_xml(bundle / "rights.xml", rights)
    return {str(path.relative_to(bundle)): digest(path) for path in sorted(bundle.rglob("*.xml"))}


def samples(serial):
    """@brief Reassemble only driver stdout and compare both encoded results with their physics samples."""
    chunks = re.findall(r'^INFO Driver "unitree" diagnostic generation 1 stdout (".*")$', serial, re.MULTILINE)
    lines = "".join(json.loads(chunk) for chunk in chunks).splitlines()
    sources, results, events = [], [], []
    for line in lines:
        a = re.fullmatch(r"MUJOCO_SOURCE tick=(\d+) sensor_bits=([0-9a-f]{8})", line)
        b = re.fullmatch(r"SENSOR_RESULT seq=(\d+) tick=(\d+) position_bits=([0-9a-f]{8})", line)
        if a:
            sources.append((int(a[1]), a[2]))
            events.append("source")
        if b:
            results.append((int(b[1]), int(b[2]), b[3]))
            events.append("result")
    if (lines.count("SENSOR_SESSION release reads=2") != 1 or events != ["source", "result", "source", "result"] or [r[0] for r in results] != [1, 2]
            or sources != [r[1:] for r in results] or not 0 < sources[0][0] < sources[1][0]):
        raise ValueError(f"two matching distinct live reads were required: source={sources}, TLS={results}")
    return [{"sequence": seq, "physics_tick": tick, "physics_position_bits": physics[1],
             "tls_tick": tick, "tls_position_bits": bits} for (seq, tick, bits), physics in zip(results, sources, strict=True)]


def main():
    """@brief Sign inputs offline, boot each chosen profile and record independent per-client outcomes."""
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--inputs", type=Path, required=True)
    cli.add_argument("--build", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--profile", choices=PROFILES, action="append", help="repeat to select payload profiles (default: all)")
    cli.add_argument("--engine", choices=("interpreter", "aot"), default="aot")
    cli.add_argument("--module-id", default="main", help="identity of an externally signed WrCC application")
    cli.add_argument("--app-algorithm", choices=("ES384", "Ed25519"), default="ES384")
    phase = cli.add_mutually_exclusive_group()
    phase.add_argument("--prepare-only", action="store_true", help="stage and sign the initramfs without booting it")
    phase.add_argument("--prepared", type=Path, help="boot a previously prepared image and write a new run receipt")
    args = cli.parse_args()
    p, out, build = paths(args.inputs), args.output.resolve(), args.build.resolve(strict=True)
    signing = p["signing_scratch"]
    group = qualification_environment(out, build, signing, vm_source=p["vm_source"])
    if not signing.is_dir() or signing.stat().st_uid != os.geteuid() or signing.stat().st_mode & 0o077:
        cli.error("signing_scratch must be a private project directory owned by the current user")
    app = check_build(build, p)
    if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_-]{0,126}", args.module_id):
        cli.error("invalid WSEA module ID")
    if app["kind"] != "signed-wrcc" and (args.module_id, args.app_algorithm) != ("main", "ES384"):
        cli.error("local fixture WSEA identity is main/ES384")
    profiles = args.profile or list(PROFILES)
    if len(set(profiles)) != len(profiles):
        cli.error("duplicate payload profile")
    os.umask(0o077)
    out.mkdir(mode=0o700)
    for key in ("TMPDIR", "TMP", "TEMP"):
        os.environ[key] = str(out)
    if args.prepared:
        prepared = args.prepared.resolve(strict=True)
        qualification_environment(prepared, vm_source=p["vm_source"])
        receipt = json.loads((prepared / "prepared.json").read_bytes())
        initrd = prepared / "initramfs.cpio.gz"
        require_digest(initrd, receipt["initramfs_sha256"])
        if (receipt["build_sha256"] != digest(build / "build.json") or receipt["client"] != app["kind"]
                or (receipt["module_id"], receipt["algorithm"], receipt["engine"]) != (args.module_id, args.app_algorithm, args.engine)
                or set(profiles) - receipt["manifests"].keys()):
            cli.error("prepared image does not contain the requested application and profiles")
        for path in (p["qemu"], p["bios"], p["kernel"]):
            require_digest(path, receipt["tools"][str(path)])
    else:
        root = out / "root"
        closure = stage_root(p, build, root)
        (root / "etc/wasm-identity").write_text(f"{args.module_id} {args.app_algorithm}\n")
        with tempfile.TemporaryDirectory(dir=signing) as directory:
            signed, signatures = sign_inputs(p, build, root, app, Path(directory))
        manifests = {name: deployment(p, root, signed, name, args.module_id, args.engine) for name in profiles}
        initrd = out / "initramfs.cpio.gz"
        pack(root, initrd)
        receipt = {"client": app["kind"], "engine": args.engine, "module_id": args.module_id,
                   "algorithm": args.app_algorithm, "build_sha256": digest(build / "build.json"),
                   "signed_inputs": signatures, "closure": closure, "manifests": manifests, "initramfs_sha256": digest(initrd),
                   "tools": inventory([Path(__file__).resolve(), SUPPORT.parent / "unitree_live_build.py", p["driver_config"],
                                       SUPPORT.parent / "qemu_supervisor.py", SUPPORT.parent / "vendor_unitree_qemu.py",
                                       p["vm_source"] / "test/0073.ros-tests/support/source/security_wsea/algorithm_matrix.py",
                                       p["qemu"], p["bios"], p["kernel"]])}
        prepared_receipt = out / "prepared.json"
        prepared_receipt.write_text(json.dumps(receipt, indent=2) + "\n")
        if args.prepare_only:
            print(prepared_receipt)
            return
    argv = [p["qemu"], "-nodefaults", "-machine", "q35", "-accel", "kvm", "-cpu", "host", "-smp", "2", "-m", "2048",
            "-display", "none", "-serial", "stdio", "-monitor", "none", "-nic", "none", "-no-reboot",
            "-bios", p["bios"], "-L", p["firmware_directory"], "-kernel", p["kernel"], "-initrd", initrd]
    receipt.update(complete=False, cgroup=str(group), cases={})
    result_path = out / "results.json"
    try:
        for name in profiles:
            cmd = [*argv, "-append", "console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all wros_case=" + name]
            log = out / (name + "-serial.log")
            case = {"argv": list(map(str, cmd)), "serial": log.name, "passed": False}
            receipt["cases"][name] = case
            try:
                with log.open("wb") as stream:
                    status = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, timeout=160)
                case["qemu_exit"] = status.returncode
                serial = log.read_text(errors="replace")
                if status.returncode or serial.splitlines().count(f"WROS_UNITREE_LIVE_PASS {name}") != 1:
                    raise ValueError(f"offline guest failed, see {log}")
                case.update(samples=samples(serial), passed=True)
            except (ValueError, subprocess.TimeoutExpired) as failure:
                case["error"] = str(failure)
            finally:
                if log.is_file():
                    case["serial_sha256"] = digest(log)
        receipt["complete"] = all(case["passed"] for case in receipt["cases"].values())
    finally:
        result_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(result_path)
    if not receipt["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
