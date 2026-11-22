#!/usr/bin/env python3
"""Qualify a declared three-module call chain with a genuine WSEA signer and VM."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET


sys.dont_write_bytecode = True
from vendor_qualification import qualification_environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("deployer", "cosign", "vm", "vm-source", "output", "trust-directory"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--wat2wasm", default="wat2wasm")
    args = parser.parse_args()
    out, trust = args.output.resolve(), args.trust_directory.resolve()
    vm_source = args.vm_source.resolve(strict=True)
    fixture_path = vm_source / "test/0073.ros-tests/support/source/security_wsea/algorithm_matrix.py"
    if not fixture_path.is_file():
        parser.error("--vm-source must be the VM source tree containing the WSEA fixtures")
    if any(checkout.is_relative_to(temp) for checkout in (vm_source, Path(__file__).resolve())
           for temp in ("/tmp", "/var/tmp", "/dev/shm")):
        parser.error("the VM and deployer sources must reside on project disks")
    qualification_environment(out, trust, vm_source=vm_source)
    os.umask(0o077)
    out.mkdir(mode=0o700, exist_ok=False)
    trust.mkdir(mode=0o700, exist_ok=False)
    bundle, pol, scratch = out / "bundle", trust / "policies", trust / "scratch"
    for location in (bundle, pol, scratch):
        location.mkdir(mode=0o700)
    cases = []

    def check(label, command, success=True, message=None):
        result = subprocess.run([str(arg) for arg in command], capture_output=True, timeout=120)
        entry = dict(case=label, code=result.returncode, stdout=result.stdout.decode(errors="replace"),
                     stderr=result.stderr.decode(errors="replace"))
        cases.append(entry)
        (out / "results.json").write_text(json.dumps(cases, indent=2))
        assert (result.returncode == 0) == success, (label, entry)
        if message:
            assert message in entry["stdout"] + entry["stderr"], (label, entry)
        return entry["stdout"]

    spec = importlib.util.spec_from_file_location("wsea_fixtures", fixture_path)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    ca = fixture.Fixtures(trust / "temporary-authority").pki("chain", family="ED25519")
    cosign = [args.cosign.resolve(), "wasm", "secure"]
    policy = pol / "admission.policy"
    primary_state = trust / "operator-state"
    vm_state = trust / "guest-state"
    vm_state.mkdir(mode=0o700)
    ids = {key: f"example.chain.{key}" for key in ("main", "bridge", "leaf", "guard")}
    for stage, policy_file, state_dir in (("operator", policy, primary_state), ("runtime", pol / "runtime.policy", vm_state)):
        check("initialize " + stage + " policy", [*cosign, "policy-init", "--output", policy_file, "--trust-root", ca["root"],
              "--state-dir", state_dir, "--certificate", ca["certificate"], "--module-id", ids["main"], "--algorithms", "Ed25519"])
        for version, key in enumerate(("bridge", "leaf", "guard"), 2):
            check("extend " + stage + " policy " + key, [*cosign, "policy-update", "--policy", policy_file, "--policy-version", version,
                  "--module-id", ids[key], "--certificate", ca["certificate"], "--algorithms", "Ed25519"])
    now = datetime.datetime.now(datetime.timezone.utc)

    def stamp(seconds):
        return (now + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def wasm(name, wat, *features):
        source = out / (name + ".wat")
        source.write_text(wat)
        target = bundle / (name + ".unsigned.wasm")
        check("assemble " + name, [args.wat2wasm, *features, source, "-o", target])
        return target

    def sign(name, source):
        target = bundle / (name + ".wasm")
        check("sign " + name, [*cosign, "sign", source, "--policy", policy, "--key", ca["key"], "--certificate", ca["certificate"],
             "--crl", ca["crl"], "--module-id", ids[name], "--module-version", "1", "--algorithm", "Ed25519",
             "--not-before", stamp(-60), "--not-after", stamp(86400), "--output", target])
        return target

    sources = {
        "leaf": '(module (func (export "value") (result i32) i32.const 40))',
        "bridge": '(module (import "leaf" "value" (func $value (result i32))) (func (export "answer") (result i32) call $value i32.const 2 i32.add))',
        "main": '(module (import "calc" "answer" (func $answer (result i32))) (func (export "_start") call $answer i32.const 42 i32.ne if unreachable end))',
    }
    sources["guard"] = sources["main"].replace("i32.const 42", "i32.const 43")
    images = {key: sign(key, wasm(key, wat)) for key, wat in sources.items()}
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    deployment = bundle / "deployment.xml"

    def declaration(key, file=None, identity=None):
        path = images[key] if file is None else file
        return {"module": path.name, "module-id": ids[key] if identity is None else identity, "sha256": digest(path),
                "policy": policy.name, "vm-policy": "runtime.policy"}

    def configure(main="main", leaf_file=None, leaf_id=None):
        root = ET.Element("deployment", {"id": "chain"})
        vm = ET.SubElement(root, "vm", {**declaration(main), "id": "body", "engine": "interpreter", "uid": "12001",
            "gid": "12001", "memory-bytes": "268435456", "pids": "16"})
        ET.SubElement(vm, "requires", {"module": "calc"})
        bridge = ET.SubElement(vm, "library", {**declaration("bridge"), "namespace": "calc"})
        ET.SubElement(bridge, "requires", {"module": "leaf"})
        ET.SubElement(vm, "library", {**declaration("leaf", leaf_file, leaf_id), "namespace": "leaf"})
        ET.ElementTree(root).write(deployment)
        return root

    def preview(label, *options, success=True, message=None, action="verify"):
        args1 = [args.deployer, action, deployment, "--policy-root", pol]
        if action == "verify":
            args1.extend(["--cosign", args.cosign.resolve(), "--scratch-directory", scratch])
        stdout = check(label, [*args1, *options], success, message)
        if success:
            return json.loads(next(line[8:] for line in stdout.splitlines() if line.startswith("VM argv ")))

    def execute(label, argv, success=True):
        return check(label, [args.vm, *argv], success)

    configure()
    argv = preview("full graph admission", message="effective host permissions: none")
    assert argv.count("named-module") == 3 and argv.count("--wasm-preload-library") == 2
    execute("three signed modules calculate 42", argv)
    execute("three signed modules calculate 42 under AOT", ["--runtime-aot" if a == "--runtime-int" else a for a in argv])
    configure(main="guard")
    execute("signed guard traps on 43", preview("signed negative guard"), False)
    configure(leaf_id=ids["guard"])
    preview("valid signed leaf bound to wrong ID", success=False, message="verified WSEA identity")
    preview("wrong verified identity cannot be waived as a signature failure", "--allow-invalid-signature", "body/leaf=" + digest(images["leaf"]), success=False, message="verified WSEA identity")
    use_wrong_id = list(argv)
    use_wrong_id[use_wrong_id.index(ids["leaf"])] = ids["guard"]
    execute("VM independently rejects valid leaf under wrong ID", use_wrong_id, False)
    unsigned_leaf = bundle / "leaf.unsigned.wasm"
    configure(leaf_file=unsigned_leaf)
    preview("unsigned leaf rejected", success=False, message="Unsigned")
    preview("a VM waiver cannot admit a leaf", "--allow-unsigned", "body=" + digest(images["main"]), success=False, message="Unsigned")
    approved = preview("only the leaf waiver selected", "--allow-unsigned", "body/leaf=" + digest(unsigned_leaf))
    assert approved.count("named-module") == 2 and approved.count("--wasm-preload-library") == 2
    execute("single waived leaf keeps signed main and bridge", approved)
    preview("wrong leaf digest never matches exception", "--allow-unsigned", "body/leaf=" + "0" * 64, success=False, message="does not match")
    preview("wrong exception class", "--allow-invalid-signature", "body/leaf=" + digest(unsigned_leaf), success=False, message="Unsigned")

    invalid = bundle / "leaf.invalid.wasm"
    signed_bytes = images["leaf"].read_bytes()
    start = signed_bytes.index(bytes.fromhex("41280b"))
    invalid.write_bytes(signed_bytes[:start] + bytes.fromhex("41290b") + signed_bytes[start + 3:])
    configure(main="guard", leaf_file=invalid)
    preview("changed signed code needs an invalid-signature waiver", success=False, message="Invalid")
    preview("unsigned waiver cannot admit changed signed code", "--allow-unsigned", "body/leaf=" + digest(invalid),
            success=False, message="Invalid")
    approved = preview("exact invalid-signature waiver selects only changed leaf", "--allow-invalid-signature", "body/leaf=" + digest(invalid))
    assert approved.count("named-module") == 2
    execute("changed leaf returns 41 and signed guard observes 43", approved)

    def bad_xml(label, mutate, message):
        root = configure()
        mutate(root.find("vm"))
        ET.ElementTree(root).write(deployment)
        preview(label, success=False, message=message, action="plan")

    bad_xml("unreachable leaf", lambda vm: vm.find("library").remove(vm.find("library/requires")), "unreachable")
    bad_xml("undeclared namespace", lambda vm: vm.find("requires").set("module", "absent"), "undeclared Wasm library")
    bad_xml("cycle", lambda vm: ET.SubElement(vm.findall("library")[1], "requires", {"module": "calc"}), "cyclic")
    bad_xml("duplicate namespace", lambda vm: vm.findall("library")[1].set("namespace", "calc"), "duplicate Wasm library")
    bad_xml("extra edge", lambda vm: ET.SubElement(vm, "requires", {"module": "leaf"}), "actual static imports")
    bad_xml("qualified digest", lambda vm: vm.findall("library")[1].set("sha256", "0" * 64), "digest mismatch")
    for label, wat, message in [
        ("wrong-signature", '(module (func (export "value") (result i64) i64.const 40))', "incompatible Wasm function"),
        ("missing-field", '(module (func (export "another") (result i32) i32.const 40))', "incompatible Wasm function"),
        ("host-clock", '(module (import "wasi_snapshot_preview1" "clock_time_get" (func)) (func (export "value") (result i32) i32.const 40))', "host import"),
        ("memory-edge", '(module (import "outside" "memory" (memory 1)) (func (export "value") (result i32) i32.const 40))', "incompatible Wasm function"),
    ]:
        file = wasm(label, wat)
        configure(leaf_file=file)
        preview(label + " remains denied under exact waiver", "--allow-unsigned", "body/leaf=" + digest(file), success=False, message=message)
    file = wasm("shared-memory", '(module (memory 1 2 shared) (func (export "value") (result i32) i32.const 40))', "--enable-threads")
    configure(leaf_file=file)
    preview("shared memory in a library is rejected", action="plan", success=False, message="unsupported Wasm library graph")
    file = bundle / "component.wasm"
    file.write_bytes(bytes.fromhex("0061736d0d000100"))
    configure(leaf_file=file)
    preview("component cannot become a core library", action="plan", success=False, message="core modules")
    # Both ends have the same field kind and type. Only the approved scalar
    # function interface may link a library into this address space.
    for name, offer, request in [
        ("memory", '(memory (export "object") 1)', '(import "leaf" "object" (memory 1))'),
        ("table", '(table (export "object") 1 funcref)', '(import "leaf" "object" (table 1 funcref))'),
        ("global", '(global (export "object") i32 i32.const 7)', '(import "leaf" "object" (global i32))'),
        ("reference", '(func (export "object") (param funcref))', '(import "leaf" "object" (func (param funcref)))'),
    ]:
        leaf = wasm("offer-" + name, "(module " + offer + ")")
        bridge = wasm("request-" + name, '(module ' + request + ' (func (export "answer") (result i32) i32.const 42))')
        root = configure(leaf_file=leaf)
        root.find("vm/library").attrib.update(declaration("bridge", bridge))
        ET.ElementTree(root).write(deployment)
        preview("matching " + name + " edge is refused", action="plan", success=False, message="incompatible Wasm function")
    configure()
    transfer = {"bundle": str(bundle), "policy": str(policy), "vm_policy": str(pol / "runtime.policy"),
                "trust_root": str(ca["root"]), "main": ids["main"], "bridge": ids["bridge"], "leaf": ids["leaf"],
                "positive": "leaf.value()=40; calc.answer()=42; body._start returns", "guard": ids["guard"]}
    (out / "transfer.json").write_text(json.dumps(transfer, indent=2))
    print(json.dumps({"completed": len(cases), **transfer}, indent=2))


if __name__ == "__main__":
    main()
