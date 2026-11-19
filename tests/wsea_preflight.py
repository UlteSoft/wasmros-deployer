"""Exercise the released verifier and the real VM with a private, short-lived test CA."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("deployer", "cosign", "vm", "vm-source", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--sdk-module", type=Path,
                        help="Sign a compiled SDK application with the disposable test authority for a full-kernel run.")
    parser.add_argument("--sdk-source", type=Path, help="Trusted SDK checkout for the core Wasm import reader.")
    parser.add_argument("--sdk-interface-probe", type=Path, help="Completed strict all-interface fixture for this test authority")
    parser.add_argument("--local-scheduling", action="store_true", help="Sign the per-alias scheduling probe for a QEMU run")
    args = parser.parse_args()
    if args.sdk_interface_probe and not args.sdk_module:
        parser.error("--sdk-interface-probe requires --sdk-module and --sdk-source")
    if bool(args.sdk_module) != bool(args.sdk_source):
        parser.error("--sdk-module and --sdk-source must be supplied together")
    os.umask(0o077)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, exist_ok=False)
    out = args.output
    bundle = out / "bundle"
    policies = out / "policies"
    scratch = out / "scratch"
    state = out / "state"
    for folder in (bundle, policies, scratch):
        folder.mkdir(mode=0o700)
    results = []

    def check(label, cmd, allowed):
        result = subprocess.run(list(map(str, cmd)), capture_output=True, timeout=45)
        results.append(dict(name=label, argv=list(map(str, cmd)), exit=result.returncode,
                            expected_success=allowed, stderr=result.stderr.decode(errors="replace")[-1500:]))
        (out / "results.json").write_text(json.dumps(results, indent=2))
        assert (result.returncode == 0) == allowed, (label, results[-1])
        return result.stdout.decode()

    path = args.vm_source / "test/0073.ros-tests/support/source/security_wsea/algorithm_matrix.py"
    spec = importlib.util.spec_from_file_location("wros_fixture", path)
    fixture_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture_module)
    fixture = fixture_module.Fixtures(out / "test-authority")
    ca = fixture.pki("test", family="ED25519")
    policy = policies / "body.policy"
    check("operator-bootstrap", [args.cosign, "wasm", "secure", "policy-init", "--output", policy,
                                 "--state-dir", state, "--trust-root", ca["root"], "--certificate",
                                 ca["certificate"], "--module-id", "body", "--algorithms", "Ed25519"], True)

    unsigned = bundle / "unsigned.wasm"
    unsigned.write_bytes(bytes.fromhex("0061736d0100000001040160000003020100070a01065f737461727400000a040102000b0005046e6f7465"))
    signed = bundle / "body.wasm"
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = lambda delta: (now + datetime.timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")
    if args.local_scheduling:
        import local_scheduling
        local_scheduling.create(args.vm_source.resolve(), out, args.cosign, ca, check, stamp)
    check("sign", [args.cosign, "wasm", "secure", "sign", unsigned, "--policy", policy, "--key", ca["key"],
                   "--certificate", ca["certificate"], "--crl", ca["crl"], "--module-id", "body",
                   "--module-version", "1", "--algorithm", "Ed25519", "--not-before", stamp(-60),
                   "--not-after", stamp(3600), "--output", signed], True)
    if args.sdk_module is not None:
        reader_path = args.sdk_source.resolve() / "install/imports.py"
        spec = importlib.util.spec_from_file_location("wros_sdk_imports", reader_path)
        reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        snapshot = out / "sdk-input.wasm"
        with args.sdk_module.open("rb") as f:
            data = f.read((128 << 20) + 1)
        expected = [{"module": "uwvm_ros_v2", "name": "abi", "kind": 0, "params": [], "results": ["i32"]}]
        if args.sdk_interface_probe:
            proof = json.loads((args.sdk_interface_probe/"results.json").read_bytes())
            catalog = Path(__file__).resolve().parents[1]/"protocol/ros-interfaces.txt"
            abi = (args.sdk_source.resolve()/"share/abi/ros.json").read_bytes()
            schemas = json.loads(abi)
            with args.vm.open("rb") as runtime:
                vm_digest = hashlib.file_digest(runtime, "sha256").hexdigest()
            if (not proof.get("complete") or proof["wasm"] != hashlib.sha256(data).hexdigest()
                    or proof["vm"] != vm_digest
                    or proof["catalog"] != hashlib.sha256(catalog.read_bytes()).hexdigest()
                    or proof["sdk_abi"] != hashlib.sha256(abi).hexdigest()
                    or schemas["module"] != "uwvm_ros_v2"):
                raise ValueError("the reviewed ROSv2 probe inputs differ")
            expected = [{"module":"uwvm_ros_v2","name":op["name"],"kind":0,
                         "params":op["wasm_signature"]["parameters"],"results":op["wasm_signature"]["results"]}
                        for op in schemas["operations"]]
            if sorted(row["name"] for row in expected) != catalog.read_text().splitlines():
                raise ValueError("the reviewed SDK and deployer interfaces differ")
        if len(data) > 128 << 20 or sorted(reader.inspect(data), key=lambda r:r["name"]) != sorted(expected,key=lambda r:r["name"]):
            raise ValueError("SDK test module differs from its required ROSv2 imports")
        snapshot.write_bytes(data)
        sdk_input = {
            "sha256": hashlib.sha256(data).hexdigest(), "imports": expected,
            "reader_sha256": hashlib.sha256(reader_path.read_bytes()).hexdigest(),
            "wsea_capabilities": 32,
        }
        sdk_policy = policies / "sdk.policy"
        sdk_signed = bundle / "sdk.signed.wasm"
        check("sdk-policy", [args.cosign, "wasm", "secure", "policy-init", "--output", sdk_policy,
                             "--state-dir", out / "sdk-state", "--trust-root", ca["root"],
                             "--certificate", ca["certificate"], "--module-id", "sdk", "--algorithms", "Ed25519",
                             "--capabilities", "32"], True)
        check("sdk-sign", [args.cosign, "wasm", "secure", "sign", snapshot, "--policy", sdk_policy,
                           "--key", ca["key"], "--certificate", ca["certificate"], "--crl", ca["crl"],
                           "--module-id", "sdk", "--module-version", "1", "--algorithm", "Ed25519",
                           "--capabilities", "32", "--not-before", stamp(-60), "--not-after", stamp(3600),
                           "--output", sdk_signed], True)
        check("sdk-verify", [args.cosign, "wasm", "secure", "verify", sdk_signed, "--policy", sdk_policy], True)
        sdk_input["signed_sha256"] = hashlib.sha256(sdk_signed.read_bytes()).hexdigest()
        (out / "sdk-input.json").write_text(json.dumps(sdk_input, indent=2))
    deployment = bundle / "deployment.xml"

    def configure(file, digest=None):
        root = ET.Element("deployment", id="cell")
        ET.SubElement(root, "vm", id="body", module=file.name, policy=policy.name,
                      sha256=digest or hashlib.sha256(file.read_bytes()).hexdigest(),
                      **{"memory-bytes": "268435456", "pids": "8"})
        ET.ElementTree(root).write(deployment)

    verify = [args.deployer, "verify", deployment, "--policy-root", policies,
              "--cosign", args.cosign.resolve(), "--scratch-directory", scratch]

    def run_vm(file, allowed):
        check("VM-" + file.stem, [args.vm, "--secure", "module", file, policy, "--run", file], allowed)

    configure(signed)
    def checked_preview(label, file, option, allowed, secondary):
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        stdout = check(label, [*verify, option, "body=" + digest], allowed)
        if allowed:
            args_line = next(line for line in stdout.splitlines() if line.startswith("VM argv "))
            argv = json.loads(args_line.removeprefix("VM argv "))
            assert ("--secure" in argv) == secondary
            assert "WARNING" in results[-1]["stderr"]
            check(label + "-actual-vm", [args.vm, *argv], True)

    check("deployer-accepts-signed", verify, True)
    checked_preview("valid-keeps-secondary", signed, "--allow-invalid-signature", True, True)
    run_vm(signed, True)
    configure(unsigned)
    check("deployer-rejects-unsigned", verify, False)
    run_vm(unsigned, False)
    checked_preview("unsigned-exception", unsigned, "--allow-unsigned", True, False)
    checked_preview("unsigned-rejects-wrong-exception", unsigned, "--allow-invalid-signature", False, False)
    changed = bundle / "changed.wasm"
    # Change an inert custom-section name, preserving guest instructions and the original signature.
    contents = signed.read_bytes()
    assert contents.count(b"note") == 1
    changed.write_bytes(contents.replace(b"note", b"meta", 1))
    configure(changed)
    check("deployer-rejects-changed-signed-bytes", verify, False)
    run_vm(changed, False)
    checked_preview("invalid-exception", changed, "--allow-invalid-signature", True, False)
    checked_preview("changed-rejects-unsigned-exception", changed, "--allow-unsigned", False, False)
    check("stale-exception-digest", [*verify, "--allow-invalid-signature", "body=" + "0" * 64], False)
    configure(signed, "0" * 64)
    check("deployer-rejects-wrong-upload-hash", verify, False)
    configure(signed)
    (bundle / policy.name).write_bytes(policy.read_bytes())
    check("bundle-cannot-provision-trust", [str(v) if v != policies else str(bundle) for v in verify], False)
    link = bundle / "linked.wasm"
    link.symlink_to(signed)
    configure(link)
    check("reject-module-symlink", verify, False)
    assert not list(scratch.iterdir()), "a verifier snapshot survived the operation"
    print(f"{len(results)} real command outcomes matched; staging empty")


if __name__ == "__main__":
    main()
