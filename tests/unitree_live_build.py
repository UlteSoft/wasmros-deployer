#!/usr/bin/env python3
"""@file unitree_live_build.py
@brief Build the managed Go2 simulator ELF and select an independently identifiable Wasm client.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from qemu_supervisor import digest
from vendor_qualification import qualification_environment
from vendor_unitree_mujoco import BRIDGE_REVISION, PINNED_INPUTS, require_digest
from vendor_unitree_qemu import CLOCK_INTERFACES, DRIVER_INTERFACES, REVISION

SUPPORT = Path(__file__).resolve().with_name("support")
SDK_HEADER_REVISION = "b7fec6020eb93d4c059a6edf19905e12a75a8d3d"
ANGLES_HEADER = "ba38ea65e3fa47316ef00b1194a8d48c186180c662945fa9ed450f1e526a030a"
MUJOCO_LIBRARY = "libmujoco.so.3.4.0"
MUJOCO_SHA256 = "427708263f6b56878ce4f24cec5d08f5561b5fe9eae3e9b5fd35df8a3d31552e"
PROFILES = {"profile-default": (24, 24), "reply-128": (24, 128), "request-128-reply-1024": (128, 1024)}


def paths(config):
    """@brief Resolve local paths relative to a JSON file and preserve compiler and QEMU launcher names."""
    base = config.resolve().parent
    return {key: (base / value).absolute() if key in ("qemu", "cxx", "wrcc", "wrwat") else (base / value).resolve()
            for key, value in json.loads(config.read_bytes()).items()}


def inventory(files):
    """@brief Identify exact regular-file inputs without retaining vendor bytes."""
    return {str(path): digest(path) for path in sorted(set(files))}


def tree_digest(root):
    """@brief Bind sorted relative path bytes and their binary SHA-256 digests."""
    value = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        value.update(path.relative_to(root).as_posix().encode() + b"\0" + bytes.fromhex(digest(path)))
    return value.hexdigest()


def execute(argv):
    """@brief Run one bounded compiler or assembler invocation."""
    command = list(map(str, argv))
    subprocess.run(command, check=True, timeout=240)
    return command


def vendor_inputs(p):
    """@brief Check the original SDK, bridge, C++ wrapper headers and MuJoCo library."""
    sdk, headers, bridge, mujoco = (p[key] for key in ("sdk", "sdk_headers", "bridge", "mujoco"))
    trees = {
        sdk / "include": "4998ec9e6e6628a60cddc4e176564a5d58694da39c13ce61e8619e174d9ec41c",
        sdk / "thirdparty/include": "be17c9e2c623fd9ac2ff6a8635c82ad1b4d1f6690f81670e6d36860ad4664550",
        headers / "unitree": "ed909266e798124064e4c68dfc98b1583bf8587ad76ffe0e50828ef19d6b70f9",
        mujoco / "include/mujoco": "33fdacc4d9107085d3859586d323d8f3bdcafc68ab5c083f91fded5a08c32df6",
    }
    for root, expected in trees.items():
        if tree_digest(root) != expected:
            raise ValueError(f"unexpected native headers: {root}")
    libraries = sdk / "thirdparty/lib/x86_64"
    files = {
        sdk / "lib/x86_64/libunitree_sdk2.a": PINNED_INPUTS["libunitree_sdk2.a"],
        libraries / "libddsc.so": PINNED_INPUTS["libddsc.so"],
        libraries / "libddscxx.so": PINNED_INPUTS["libddscxx.so"],
        mujoco / MUJOCO_LIBRARY: MUJOCO_SHA256,
        bridge / "unitree_sdk2_bridge.h": "8bd7a48e0e66738359b6c75ca4f2f4760b0670012a86a86a7b8396a3a5bfeaad",
        bridge / "param.h": "c57b9484be615da7fe24ca90312f781de9ff13872cf8adca41ae61510dd4445e",
        bridge / "physics_joystick.h": "ae04689f1f4479e175119f9919b3134f0ddff07963f5ebd21278a66318a39475",
        bridge / "joystick/joystick.cc": "d06f23ae5b2a94707772fc2473c4031f2552e34f0578bfe5b857efb5b76af1d9",
        bridge / "joystick/joystick.h": "83eceee28b9e0a87571cfad9c353f27a662ab9b52edbe9bc948ce06fd7955d9b",
    }
    for path, expected in files.items():
        require_digest(path, expected)
    return {str(path): value for path, value in files.items()}, {str(path): value for path, value in trees.items()}


def build_provider(p, output):
    """@brief Link the unmodified upstream Go2Bridge with its observation-only channel transport."""
    files, trees = vendor_inputs(p)
    sdk, ssl, vm = p["sdk"], p["openssl_root"], p["vm_source"]
    bridge, mujoco, compiler = p["bridge"], p["mujoco"], p["cxx"]
    sources = [SUPPORT / name for name in ("unitree_live_main.cpp", "unitree_attachment.cpp", "unitree_live_simulator.cpp")]
    sources.append(bridge / "joystick/joystick.cc")
    command = [compiler, "-std=c++23", "-O3", "-g", "-pthread", "-DUWVM_ROS_ATTACHMENT_OPENSSL",
               "-DWROS_UNITREE_IN_PROCESS_SIMULATOR", "-I", SUPPORT / "unitree_local_transport", "-I", vm / "src"]
    for directory in (vm / "third-parties/fast_io/include", ssl / "include", bridge, bridge / "joystick",
                      mujoco / "include", p["boost_include"], p["yaml_include"], p["eigen_include"],
                      p["sdk_headers"], sdk / "include", sdk / "thirdparty/include", sdk / "thirdparty/include/ddscxx"):
        command.extend(("-isystem", directory))
    # Dependency files include system and SDK headers actually read by this compiler.
    objects, commands = [], []
    for source in sources:
        obj = output / (source.stem + ".o")
        dep = obj.with_suffix(".d")
        commands.append(execute([*command, "-MD", "-MF", dep, "-c", source, "-o", obj]))
        # Clang escapes spaces in GNU make dependencies and folds long lines.
        _, _, dependencies = dep.read_text().replace("\\\n", " ").partition(": ")
        files.update(inventory(Path(name) for name in shlex.split(dependencies)))
        objects.append(obj)
    ssl_libraries = [ssl / "libssl.a", ssl / "libcrypto.a"]
    commands.append(execute([compiler, "-pthread", *objects, sdk / "lib/x86_64/libunitree_sdk2.a",
                             *ssl_libraries, "-L", mujoco, "-L", sdk / "thirdparty/lib/x86_64",
                             "-lddscxx", "-lddsc", f"-l:{MUJOCO_LIBRARY}", "-ldl", "-Wl,-rpath,/opt/unitree",
                             "-o", output / "unitree-provider"]))
    files.update(inventory([compiler, *ssl_libraries]))
    return {"sdk": REVISION, "bridge": BRIDGE_REVISION, "wrapper_sdk": SDK_HEADER_REVISION,
            "mujoco": "3.4.0", "inputs": files, "header_trees": trees, "commands": commands,
            "sha256": digest(output / "unitree-provider")}


def strict_receipt(path, wasm, vm):
    """@brief Bind a strict wasm32 C++ MTE build receipt to the unsigned application and actual VM."""
    receipt = json.loads(path.read_bytes())
    profile = receipt["profile"]
    if (receipt["format"] != "wros-build-receipt" or receipt["language"] != "cpp" or receipt["mode"] != "strict"
            or profile["address_bits"] != 32 or profile["mte"] is not True or profile["threads"] is not False
            or not re.fullmatch("[a-f0-9]{64}", receipt["release_sha256"])
            or receipt["artifact_sha256"] != digest(wasm) or receipt["vm_sha256"] != digest(vm)):
        raise ValueError("WrCC receipt does not bind this application, strict profile and runtime")
    return receipt


def build_client(p, output, client):
    """@brief Select the live WAT entry, compile ROS angles with WrCC, or retain a signed WrCC input."""
    wasm = output / "controller.wasm"
    external = {}
    if client == "live-wat":
        origin = SUPPORT / "unitree_low_state.wat"
        source = output / "controller.wat"
        entry = '(export "_start" (func $recorded))'
        text = origin.read_text()
        if text.count(entry) != 1:
            raise ValueError("missing the tutorial WAT entry declaration")
        source.write_text(text.replace(entry, '(export "_start" (func $live))'))
        argv = [p["wrwat"], source, "-g", "--build-receipt", "-o", wasm]
        for name in (*DRIVER_INTERFACES, *CLOCK_INTERFACES):
            argv.extend(("--ros-operation", name))
        command = execute(argv)
        receipt = json.loads(wasm.with_suffix(".wasm.wros-wat.json").read_bytes())
        if (receipt["wasm_sha256"] != digest(wasm) or receipt["source_sha256"] != digest(source)
                or set(receipt["ros_operations"]) != set((*DRIVER_INTERFACES, *CLOCK_INTERFACES))):
            raise ValueError("Wrwat output or declared interfaces differ from its receipt")
        files = [p["wrwat"], origin, source]
    elif client == "ros-angles":
        header = p["angles_include"] / "angles/angles.h"
        require_digest(header, ANGLES_HEADER)
        source = SUPPORT / "unitree_angles_guest.cpp"
        command = execute(["/usr/bin/python3", "-I", "-B", p["wrcc"], "--target", "wasm32", "--std", "c++23", "-O3", "-g", "--mte",
                           "--reactor", "--export", "_start", "--build-receipt", "-I", p["angles_include"],
                           source, "-o", wasm])
        receipt = strict_receipt(wasm.with_suffix(".wasm.wros-build.json"), wasm, p["vm"])
        files = [p["wrcc"], header, source, p["vm"]]
    else:
        shutil.copyfile(p["unsigned_app"], wasm)
        receipt = strict_receipt(p["wrcc_receipt"], wasm, p["vm"])
        if not p["signed_app"].read_bytes().startswith(wasm.read_bytes()) or p["signed_app"].stat().st_size <= wasm.stat().st_size:
            raise ValueError("the signed module must contain the exact strict WrCC output")
        external = {name: digest(p[name]) for name in ("signed_app", "app_root", "app_signer")}
        files = [p[name] for name in ("unsigned_app", "signed_app", "wrcc_receipt", "app_root", "app_signer", "vm")]
        command = None
    return {"kind": client, "sha256": digest(wasm), "receipt": receipt, "inputs": inventory(files), "command": command, "external": external}


def main():
    """@brief Build in a fresh project scratch directory without launching any fixture or guest."""
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--inputs", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    cli.add_argument("--client", choices=("live-wat", "ros-angles", "signed-wrcc"), required=True)
    args = cli.parse_args()
    p, out = paths(args.inputs), args.output.resolve()
    qualification_environment(out, vm_source=p["vm_source"])
    os.umask(0o077)
    out.mkdir(mode=0o700)
    for key in ("TMPDIR", "TMP", "TEMP"):
        os.environ[key] = str(out)
    provider = build_provider(p, out)
    client = build_client(p, out, args.client)
    row = {"builder_sha256": digest(Path(__file__)), "provider": provider, "application": client}
    (out / "build.json").write_text(json.dumps(row, indent=2) + "\n")


if __name__ == "__main__":
    main()
