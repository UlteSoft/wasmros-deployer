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
    args = parser.parse_args()
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
    unsigned.write_bytes(bytes.fromhex("0061736d0100000001040160000003020100070a01065f737461727400000a040102000b"))
    signed = bundle / "body.wasm"
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = lambda delta: (now + datetime.timedelta(seconds=delta)).strftime("%Y-%m-%dT%H:%M:%SZ")
    check("sign", [args.cosign, "wasm", "secure", "sign", unsigned, "--policy", policy, "--key", ca["key"],
                   "--certificate", ca["certificate"], "--crl", ca["crl"], "--module-id", "body",
                   "--module-version", "1", "--algorithm", "Ed25519", "--not-before", stamp(-60),
                   "--not-after", stamp(3600), "--output", signed], True)
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
    check("deployer-accepts-signed", verify, True)
    run_vm(signed, True)
    configure(unsigned)
    check("deployer-rejects-unsigned", verify, False)
    run_vm(unsigned, False)
    changed = bundle / "changed.wasm"
    # Rename the exported guest entry while preserving the embedded original signature.
    contents = signed.read_bytes()
    assert contents.count(b"_start") == 1
    changed.write_bytes(contents.replace(b"_start", b"_other", 1))
    configure(changed)
    check("deployer-rejects-changed-signed-bytes", verify, False)
    run_vm(changed, False)
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
