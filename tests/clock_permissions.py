"""Run the deployer's per-VM clock policies against signed core Wasm in the real VM."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from deployment_review import terminal_run

CLOCKS = ("realtime", "monotonic", "process", "thread")


def wat(bits, access):
    ptr = f"i{bits}"
    suffix = "_wasm64" if bits == 64 else ""
    lines = ["(module",
             f'(import "wasi_snapshot_preview1" "clock_time_get{suffix}" (func $time (param i32 i64 {ptr}) (result i32)))',
             f'(import "wasi_snapshot_preview1" "clock_res_get{suffix}" (func $res (param i32 {ptr}) (result i32)))',
             "(memory i64 1)" if bits == 64 else "(memory 1)", '(func (export "_start")']
    for index, clock in enumerate(CLOCKS):
        for kind, call in (("clock", "time"), ("resolution", "res")):
            allowed = clock + "-" + kind in access
            # A rejected read must leave the destination unchanged.
            lines += [f"{ptr}.const 8 i64.const -1 i64.store", f"i32.const {index}"]
            if kind == "clock":
                lines.append("i64.const 1")
            lines += [f"{ptr}.const 8 call ${call} i32.const {0 if allowed else 76} i32.ne if unreachable end",
                      f"{ptr}.const 8 i64.load i64.const -1 {'i64.eq' if allowed else 'i64.ne'} if unreachable end"]
    return "\n".join(lines) + "))\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("deployer", "vm", "cosign", "vm-source", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--legacy-vm-wasm64-signature-class", action="store_true",
                        help="exercise old VMs that group wasm64 clock names with unknown WASI imports; test signing only")
    a = parser.parse_args()
    group = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().split("::")[1].lstrip("/")
    assert (group / "memory.max").read_text().strip() == "68719476736"
    assert (group / "memory.swap.max").read_text().strip() == "0"
    os.umask(0o077)
    out = a.output.resolve()
    if ".tmp" not in out.parts:
        parser.error("choose a new qualification directory under a project .tmp")
    out.mkdir(mode=0o700, exist_ok=False)
    bundle, policies, scratch = (out / n for n in ("bundle", "policies", "scratch"))
    for directory in (bundle, policies, scratch):
        directory.mkdir(mode=0o700)
    source = a.vm_source.resolve() / "test/0073.ros-tests/support/source/security_wsea/algorithm_matrix.py"
    spec = importlib.util.spec_from_file_location("wros_test_pki", source)
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    ca = fixtures.Fixtures(out / "test-authority").pki("clock", family="ED25519")
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    engines = ("interpreter", "aot")
    commands, cases = [], []
    report = {"complete": False, "cgroup": str(group), "commands": commands, "cases": cases,
              "legacy_vm_wasm64_signature_class": a.legacy_vm_wasm64_signature_class,
              "inputs": {str(p): sha(p) for p in (source, Path(__file__), a.vm, a.cosign, a.deployer)}}

    def save():
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(label, args, expected=True):
        cmd = list(map(str, args))
        r = subprocess.run(cmd, capture_output=True, timeout=90)
        commands.append({"label": label, "argv": cmd, "exit": r.returncode})
        (out / (label + ".log")).write_bytes(r.stdout + r.stderr)
        save()
        if (r.returncode == 0) != expected:
            raise RuntimeError(label + ": " + (r.stdout + r.stderr).decode(errors="replace")[-1600:])
        return r.stdout.decode(), r.stderr.decode(errors="replace")

    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = lambda seconds: (now + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    all_grants = [c + "-" + kind for c in CLOCKS for kind in ("clock", "resolution")]
    manifest = bundle / "deployment.xml"
    for bits in (32, 64):
        names = ["wasip1.clock_time_get", "wasip1.clock_res_get"]
        if bits == 64:
            names = [s + "_wasm64" for s in names]
        ids = {}
        for variant, allowed in (("all", all_grants), ("split", all_grants[::3]), ("zero", []),
                                 ("signedzero", []), ("unknown", [])):
            id_ = f"{variant}{bits}"
            assembly = out / (id_ + ".wat")
            text = wat(bits, allowed)
            if variant == "unknown":
                name = names[0].removeprefix("wasip1.")
                text = text.replace('"' + name + '"', '"' + name + '_unknown"')
            assembly.write_text(text)
            unsigned, signed = out / (id_ + ".wasm"), bundle / (id_ + ".signed.wasm")
            policy = policies / (id_ + ".policy")
            run(id_ + "-assemble", ["wat2wasm", "--enable-memory64", assembly, "-o", unsigned])
            cap = "33" if bits == 64 and a.legacy_vm_wasm64_signature_class else "1"
            if variant == "signedzero":
                cap = "0"
            if variant == "unknown":
                cap = "1"
            run(id_ + "-policy", [a.cosign, "wasm", "secure", "policy-init", "--output", policy,
                "--state-dir", out / (id_ + "-state"), "--trust-root", ca["root"], "--certificate", ca["certificate"],
                "--module-id", id_, "--algorithms", "Ed25519", "--capabilities", cap])
            run(id_ + "-sign", [a.cosign, "wasm", "secure", "sign", unsigned, "--policy", policy,
                "--key", ca["key"], "--certificate", ca["certificate"], "--crl", ca["crl"],
                "--module-id", id_, "--module-version", "1", "--algorithm", "Ed25519", "--capabilities", cap,
                "--not-before", stamp(-60), "--not-after", stamp(3600), "--output", signed])
            ids[variant] = (signed, policy, allowed)
        for engine in engines:
            plan = ET.Element("deployment", id="cell")
            expected = {}
            for mode in ("all", "split", "zero", "hidden", "denied", "signedzero", "unknown"):
                variant = mode if mode in ids else "zero"
                signed, policy, allowed = ids[variant]
                id_ = mode + str(bits)
                fields = dict(id=id_, engine=engine, module=signed.name, sha256=sha(signed),
                              policy=policy.name, pids="8")
                fields["memory-bytes"] = "134217728"
                if mode != "hidden":
                    rec = ET.Element("recommendations")
                    for name in names:
                        ET.SubElement(rec, "interface", name=name, expose="deny" if mode == "denied" else "allow")
                    for name in all_grants:
                        if name in allowed or mode == "denied":
                            ET.SubElement(rec, "wasip1-clock", name=name, access="allow")
                        elif mode == "split":
                            ET.SubElement(rec, "wasip1-clock", name=name, access="deny")
                    path = bundle / (id_ + "-rights.xml")
                    ET.ElementTree(rec).write(path)
                    fields["recommendations"] = path.name
                ET.SubElement(plan, "vm", fields)
                expected[id_] = mode
            ET.ElementTree(plan).write(manifest)
            label = f"{engine}-{bits}"
            base = [manifest, "--policy-root", policies, "--cosign", a.cosign, "--scratch-directory", scratch]
            stdout, problems = run(label + "-verify", [a.deployer, "verify", *base], expected=False)
            for mode in ("hidden", "unknown"):
                if f'STARTUP BLOCKED for VM "{mode}{bits}"' not in problems:
                    raise ValueError(f"deployer did not reject {mode} before launch")
            # Use the dry-run vectors below to exercise the real VM's independent gate.
            previews = [json.loads(line[len("VM argv "):]) for line in stdout.splitlines() if line.startswith("VM argv ")]
            if len(previews) != len(expected):
                raise ValueError("missing per-VM launch plan")
            for argv in previews:
                id_ = argv[argv.index("--wasm-set-main-module-name") + 1]
                mode = expected.pop(id_)
                if "--secure" not in argv or any(x.startswith("--wasip1-global") or x.startswith("--wasip1-group") for x in argv):
                    raise ValueError("signature review or per-VM isolation missing")
                if ("--wasip1-single-enable" in argv) != (mode != "hidden"):
                    raise ValueError("unexpected WASIp1 namespace grant")
                _, stderr = run(label + "-" + mode, [a.vm, *argv], expected=mode not in ("hidden", "signedzero", "unknown"))
                if mode == "signedzero" and "POL_003" not in stderr:
                    raise ValueError("a signed mask without WASI did not hit the capability gate")
                denial = None
                if mode == "signedzero":
                    denial = "WSEA capability"
                if mode == "unknown":
                    if "_unknown" not in stderr:
                        raise ValueError("the unknown clock name did not appear in the rejection")
                    if "unknown host interface" in stderr:
                        denial = "unregistered host interface"
                    elif "POL_003" in stderr:
                        denial = "WSEA capability"
                    else:
                        raise ValueError("unexpected refusal for the unknown clock import")
                if mode == "hidden" and "clock_" not in stderr:
                    raise ValueError("hidden clock guest did not report the missing import")
                cases.append({"width": bits, "engine": engine, "policy": mode,
                              "denial": "hidden import" if mode == "hidden" else denial})
                save()
    # Exercise manual review with a real terminal and no recommendations.
    plan = ET.Element("deployment", id="manual")
    signed = bundle / "all32.signed.wasm"
    ET.SubElement(plan, "vm", id="manual", module=signed.name, sha256=sha(signed), policy="all32.policy",
                  **{"memory-bytes": "134217728", "pids": "8"})
    ET.ElementTree(plan).write(manifest)
    command = list(map(str, (a.deployer, "review", manifest, "--policy-root", policies)))
    code, log = terminal_run(command, b"allow wasip1.clock_time_get\nallow wasip1.clock.monotonic-clock\n"
                             b"allow wasip1.clock.realtime-clock\ndeny wasip1.clock.realtime-clock\n"
                             b"remove wasip1.clock.realtime-clock\nallow wasip1.sock_open\ndeny wasip1.clock_res_get\nconfirm\n")
    (out / "manual.log").write_text(log)
    commands.append({"label": "manual", "argv": command, "exit": code})
    if code or "registered interface" not in log:
        raise ValueError("manual permission review did not reject an unsupported key")
    line, = [line for line in log.splitlines() if line.startswith("VM argv ")]
    argv = json.loads(line.removeprefix("VM argv "))
    start = argv.index("--wasip1-single-create")
    expected = ["--wasip1-single-create", "manual", "--wasip1-single-enable", "manual",
                "--wasip1-single-grant", "manual", "monotonic-clock",
                "--wasip1-single-interface", "manual", "clock_res_get", "deny",
                "--wasip1-single-interface", "manual", "clock_time_get", "allow"]
    if argv[start:argv.index("--secure")] != expected:
        raise ValueError("manual approval modified unexpected permissions")
    report["manual_review"] = True
    report["complete"] = True
    save()
    print(len(cases), "signed per-VM clock cases passed")


if __name__ == "__main__":
    main()
