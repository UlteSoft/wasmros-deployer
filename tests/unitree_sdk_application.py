"""Build the external Go2 reader with the selected SDK and inspect its linked Wasm."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess

from qemu_supervisor import digest


DRIVER_INTERFACES = ("capability.open", "driver.connect", "driver.submit", "driver.result", "driver.disconnect")
CLOCK_INTERFACES = ("clock.create", "clock.read")
TESTS = Path(__file__).resolve().parent


def read_bounded(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"input exceeds the qualification size bound: {path}")
    return data


def sdk_inputs(sdk):
    """Check the selected compiler and import reader against the installed inventory."""
    selection_path = sdk / "selection.json"
    selection = json.loads(selection_path.read_bytes())
    if (selection["schema"] != 1 or selection["platform"] != "unitree" or selection["language"] != "c"
            or not re.fullmatch("[0-9a-f]{40}", selection["commit"])):
        raise ValueError("select a commit-pinned SDK installation for Unitree C")
    compiler = sdk / "bin/wrc"
    reader = sdk / "install/imports.py"
    abi = sdk / "share/abi/ros.json"
    contract = sdk / "platform/unitree/go2-low-state.contract"
    sysroot = sdk / "lib/wasm32-wasip1/sysroots.json"
    inputs = {str(selection_path): digest(selection_path)}
    for path in (compiler, reader, abi, contract, sysroot):
        actual = digest(path)
        if actual != selection["files"][str(path.relative_to(sdk))]["sha256"]:
            raise ValueError(f"file differs from installed SDK selection: {path}")
        inputs[str(path)] = actual
    if digest(TESTS / "support/unitree_low_state_contract.txt") != inputs[str(contract)]:
        raise ValueError("SDK and deployer Go2 attachment contracts differ")
    return {"sdk_commit": selection["commit"], "inputs": inputs}


def review(sdk, wasm, trusted, approved=None):
    """Compare the private artifact, its compiler receipt and the installed Unitree contract."""
    sidecar = Path(str(wasm) + ".wros-build.json")
    receipt_bytes = read_bounded(sidecar, 1 << 20)
    receipt_hash = hashlib.sha256(receipt_bytes).hexdigest()
    if approved is not None and receipt_hash != approved:
        raise ValueError("compiler receipt differs from the operator-approved digest")
    receipt = json.loads(receipt_bytes)
    target, = json.loads((sdk / "lib/wasm32-wasip1/sysroots.json").read_bytes())["targets"]
    closure = hashlib.sha256(json.dumps(target, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    data = read_bounded(wasm, 128 << 20)
    if (receipt["format"] != "wros-build-receipt" or receipt["language"] != "c"
            or receipt["mode"] != "instrumented" or receipt["vm_qualified"] is not False
            or receipt["profile"] != target["guest_profile"] or not receipt["profile"]["mte"]
            or receipt["compiler_sha256"] != trusted["inputs"][str(sdk / "bin/wrc")] or receipt["sysroot_sha256"] != closure
            or receipt["artifact_sha256"] != hashlib.sha256(data).hexdigest()):
        raise ValueError("public compiler receipt does not match the SDK profile, toolchain and Wasm")

    spec = importlib.util.spec_from_file_location("unitree_sdk_imports", sdk / "install/imports.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = sorted(module.inspect(data), key=lambda item: (item["module"], item["name"]))
    catalog = json.loads((sdk / "share/abi/ros.json").read_bytes())
    names = set(DRIVER_INTERFACES + CLOCK_INTERFACES)
    expected = sorted(({"module": "uwvm_ros_v2", "name": op["name"], "kind": 0,
                        "params": op["wasm_signature"]["parameters"], "results": op["wasm_signature"]["results"]}
                       for op in catalog["operations"] if op["name"] in names), key=lambda item: item["name"])
    if (catalog["module"] != "uwvm_ros_v2" or {item["name"] for item in expected} != names
            or len(expected) != len(names) or actual != expected):
        raise ValueError(f"linked imports differ from the seven reviewed Go2 function signatures: {actual}")
    return {**trusted, "artifact_sha256": receipt["artifact_sha256"], "build_receipt_sha256": receipt_hash,
            "build_receipt": receipt, "imports": actual}


def stage_approved(sdk, source, approved, output):
    """Only this private copy is submitted to the disposable signing authority."""
    if not re.fullmatch("[0-9a-f]{64}", approved):
        raise ValueError("invalid approved SDK build receipt SHA-256")
    trusted = sdk_inputs(sdk)
    output.mkdir(mode=0o700)
    wasm = output / "controller.wasm"
    wasm.write_bytes(read_bounded(source, 128 << 20))
    Path(str(wasm) + ".wros-build.json").write_bytes(read_bounded(Path(str(source) + ".wros-build.json"), 1 << 20))
    report = review(sdk, wasm, trusted, approved)
    report["approved_build_receipt_sha256"] = approved
    (output / "review.json").write_text(json.dumps(report, indent=2) + "\n")
    return wasm, report


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sdk", "sdk-project", "output"):
        parser.add_argument("--" + name, type=lambda p: Path(p).resolve(), required=True)
    args = parser.parse_args(argv)
    if ".tmp" not in args.output.parts:
        parser.error("choose a fresh build directory under project .tmp")
    os.umask(0o077)
    trusted = sdk_inputs(args.sdk)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    wasm = args.output / "controller.wasm"
    source = args.sdk_project / "main.c"
    staged = args.output / "main.c"
    staged.write_bytes(read_bounded(source, 1 << 20))
    argv = [args.sdk / "bin/wrc", "--target", "wasm32", "--core", "3.0", "--mte", "--eh", "--no-threads",
            "--memory64", "--std", "c17", "-O2", "--no-debug", "--reactor", "--export", "_start",
            "--build-receipt", staged, "-o", wasm]
    with (args.output / "compiler.log").open("xb") as log:
        subprocess.run(argv, check=True, timeout=180, cwd=args.output, stdout=log, stderr=subprocess.STDOUT,
                       env=dict(os.environ, TMPDIR=str(args.output), TMP=str(args.output), TEMP=str(args.output),
                                PYTHONDONTWRITEBYTECODE="1"))
    report = review(args.sdk, wasm, trusted)
    report["inputs"][str(source)] = digest(staged)
    report["command"] = list(map(str, argv))
    (args.output / "review.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f'{args.output / "review.json"}\nBuild receipt SHA-256 {report["build_receipt_sha256"]}')
