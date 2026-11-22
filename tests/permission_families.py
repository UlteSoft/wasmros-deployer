"""Exhaustive paired terminal review for the deployed host-namespace boundary."""
import argparse
from collections import Counter
from hashlib import file_digest, sha256
from itertools import product
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
from deployment_review import terminal_run
from vendor_qualification import qualification_environment


WASI = ("wasi_snapshot_preview1", "clock_time_get", "wasip1.clock_time_get")
ROS_V2 = ("uwvm_ros_v2", "abi", "abi")
NATIVE = ("native_fixture", "ping", "preloaddl/native_fixture")
HIDDEN = "hidden"
PRELOAD_REFUSED = "in-process native preload is unsupported (10/10 high risk)"


def fixture(families, mask, policies):
    imports, body = [], []
    for bit, (namespace, function, key) in enumerate(families):
        if not mask & (1 << bit):
            continue
        arguments = "(param i32 i64 i32)" if key == WASI[2] else ""
        imports.append(f'(import "{namespace}" "{function}" (func $op{bit} {arguments} (result i32)))')
        policy = policies[bit]
        expected = {"allow": (0, 1, 2, 0)[bit], "deny": (76, 13, 13, 0)[bit], HIDDEN: 0}[policy]
        operands = "i32.const 1 i64.const 1 i32.const 16 " if key == WASI[2] else ""
        if key == WASI[2]:
            body.append("i32.const 16 i64.const -1 i64.store")
        body.append(f"{operands}call $op{bit} i32.const {expected} i32.ne if unreachable end")
        if key == WASI[2]:
            unchanged = "i64.eq" if policy == "allow" else "i64.ne"
            body.append(f"i32.const 16 i64.load i64.const -1 {unchanged} if unreachable end")
    return "(module\n" + "\n".join(imports) + '\n(memory 1)\n(func (export "_start")\n' + "\n".join(body) + "))\n"


def status_fixture(interface, visible):
    query = struct.pack("<Q", 9) + b"preloaddl" + struct.pack("<QQ", 0, 0)
    escaped = "".join(f"\\{byte:02x}" for byte in query)
    expected = 95 if interface in ("allow", "default") and visible else 13
    values = (0, 0) if expected == 95 else (-1, -1)
    length_check = "i64.const 40 i64.lt_u" if expected == 95 else "i64.const -1 i64.ne"
    return f'''(module
      (import "uwvm_ros_v2" "permission.report"
        (func $report (param i64 i32 i64 i64 i64 i64 i64) (result i32)))
      (memory 1)
      (data (i32.const 32) "{escaped}")
      (func (export "_start")
        i32.const 128 i64.const -1 i64.store
        i32.const 136 i64.const -1 i64.store
        i32.const 8192 i64.const -1 i64.store
        i64.const 0 i32.const 0 i64.const 32 i64.const {len(query)}
        i64.const 128 i64.const 4096 i64.const 8192 call $report
        i32.const {expected} i32.ne if unreachable end
        i32.const 128 i64.load i64.const {values[0]} i64.ne if unreachable end
        i32.const 136 i64.load i64.const {values[1]} i64.ne if unreachable end
        i32.const 8192 i64.load {length_check} if unreachable end))
      '''


def digest(path):
    with path.open("rb") as f:
        return file_digest(f, "sha256").hexdigest()


def interface_xml(recommendations, key, decision):
    ET.SubElement(recommendations, "interface", name=key, expose=decision)
    if key == WASI[2]:
        ET.SubElement(recommendations, "wasip1-clock", name="monotonic-clock", access=decision)


def check_argv(argv, identity, decisions, legacy_key):
    def occurrences(word):
        return [i for i, text in enumerate(argv) if text == word]

    assert argv[argv.index("--wasm-set-main-module-name")+1] == identity
    assert not any(word.startswith(("--wasip1-global", "--wasip1-group",
                                    "--ros1-global", "--ros1-group", "--ros2-global", "--ros2-group"))
                   for word in argv)
    assert not any("preloaddl" in word or "native_fixture" in word for word in argv)
    wasi, legacy, ros = decisions[:3]
    for name, prefix, function, decision in [
        ("--wasip1-single-interface", identity, WASI[1], wasi),
        ("--ros-scene-interface", identity, ROS_V2[1], ros),
    ]:
        found = [i for i in occurrences(name) if argv[i+2] == function]
        if decision == HIDDEN and (function != "abi" or not found):
            assert not found, argv
        else:
            assert len(found) == 1 and argv[found[0]+1:found[0]+4] == [prefix, function, decision], argv
    assert "permission.report" not in argv
    for switch in ("--wasip1-single-create", "--wasip1-single-enable"):
        assert bool(occurrences(switch)) == (wasi != HIDDEN)
    for mode in ("allow", "deny"):
        flag = "--wasip1-single-" + ("grant" if mode == "allow" else "deny")
        found = occurrences(flag)
        assert bool(found) == (wasi == mode)
        if found:
            assert argv[found[0]+1:found[0]+3] == [identity, "monotonic-clock"]
    if legacy_key:
        version = "ros1" if legacy_key.startswith("uwvm_ros1") else "ros2"
        found = occurrences(f"--{version}-single-interface")
        assert bool(found) == (legacy != HIDDEN)
        if found:
            assert len(found) == 1 and argv[found[0]+1:found[0]+4] == [identity, legacy_key, legacy], argv
    else:
        assert not any(word.startswith(("--ros1-single-", "--ros2-single-")) for word in argv), argv


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ("deployer", "vm", "output"):
        p.add_argument("--"+option, type=Path, required=True)
    p.add_argument("--legacy-abi", choices=("ros1", "ros2"), action="append", default=[],
                   help="run ternary decisions for this ABI on a VM explicitly built with it; repeat for both")
    p.add_argument("--engines", choices=("interpreter", "aot"), nargs="+", default=("interpreter", "aot"))
    args = p.parse_args()
    runtime, deployer, out = args.vm.resolve(), args.deployer.resolve(), args.output.resolve()
    group = qualification_environment(out)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    out.mkdir()
    bundle, trust, recipes = out/"bundle", out/"trust", out/"recipes"
    for folder in (bundle, trust, recipes):
        folder.mkdir()
    (trust/"review-preview.policy").write_text("test preview never executes a signature policy\n")
    manifest = bundle/"deployment.xml"
    review = [deployer, "review", manifest, "--policy-root", trust]
    adopt = [*review, "--accept-recommendations-through-risk", "--risk-accept-threshold", "default"]
    aggregates = Counter()
    built = {}
    outcomes = (out/"matrix.jsonl").open("w", buffering=1)

    def artifact(source):
        key = sha256(source.encode()).hexdigest()
        if key not in built:
            wat, wasm = recipes/(key + ".wat"), bundle/(key + ".wasm")
            wat.write_text(source)
            subprocess.run(["/usr/bin/wat2wasm", wat, "-o", wasm], check=True, timeout=15)
            built[key] = (wasm, digest(wasm))
        return built[key]

    def rejected_preview():
        plan = subprocess.run([deployer, "plan", manifest, "--policy-root", trust, "--risk-report", "none"],
                              capture_output=True, text=True, timeout=30)
        assert plan.returncode != 0 and "STARTUP BLOCKED" in plan.stderr, plan.stderr
        return plan.stdout

    def pair(test, version, engine, masks, policies):
        legacy = (f"uwvm_{version}_v1", "abi_version", f"uwvm_{version}_v1.abi_version")
        optional = version in args.legacy_abi
        families = (WASI, legacy, ROS_V2, NATIVE)
        checked, answers, expected_class = [], [], []
        deployment = ET.Element("deployment", id="matrix")
        for identity, mask, decisions in zip(("left", "right"), masks, policies, strict=True):
            wasm, signature = artifact(fixture(families, mask, decisions))
            rec = ET.Element("recommendations")
            recommended, changes = {}, []
            for bit in (0, 1, 2):
                if bit == 1 and not optional:
                    continue
                key = families[bit][2]
                effective = decisions[bit]
                # Use a deliberately different default to require visible edits.
                default = "deny" if effective == "allow" else "allow"
                interface_xml(rec, key, default)
                recommended[key] = default
                verb = ("hide" if key == "abi" else "remove") if effective == HIDDEN else effective
                changes.append(f"{verb} {key}")
                if bit == 0:
                    recommended["wasip1.clock.monotonic-clock"] = default
                    changes.append(f"{verb} wasip1.clock.monotonic-clock")
            answers.extend(recommended[key] for key in sorted(recommended))
            answers.extend(changes)
            if mask & 8:
                answers.append(f"allow {NATIVE[2]}")
            if mask & 2 and not optional:
                answers.append(f"allow {legacy[0]}.time_read_ros")
            answers.append("confirm")
            rights = f"{identity}.xml"
            ET.ElementTree(rec).write(bundle/rights, encoding="utf-8")
            ET.SubElement(deployment, "vm", {
                "id": identity, "engine": engine, "module": wasm.name, "sha256": signature,
                "policy": "review-preview.policy", "recommendations": rights,
                "memory-bytes": "134217728", "pids": "8",
            })
            if mask & 8 or mask & 2 and not optional:
                expected_class.append("missing-provider")
            elif any(mask & (1 << bit) and decisions[bit] == HIDDEN for bit in (0, 1, 2)):
                expected_class.append("hidden")
            else:
                expected_class.append("success")
            if expected_class[-1] != "success":
                answers.append("cancel")  # Attempt an invalid final confirmation before leaving the editor.
        ET.ElementTree(deployment).write(manifest, encoding="utf-8")
        result, log = terminal_run(list(map(str, review)), ("\n".join(answers)+"\n").encode(), timeout=25)
        blocked = any(value != "success" for value in expected_class)
        if (result != 0) != blocked or blocked and "STARTUP BLOCKED" not in log:
            (out/"failure-review.log").write_text(log)
            raise RuntimeError("unexpected deployment review result")
        preview = log
        if blocked:
            # Materialize the attempted final edits for an independent, nonexecuting
            # preview. This gives the direct VM the exact policy refused by review.
            for identity, decisions in zip(("left", "right"), policies, strict=True):
                candidate = ET.Element("recommendations")
                for bit, (_, _, key) in enumerate(families[:3]):
                    if bit == 1 and not optional: continue
                    if decisions[bit] != HIDDEN or key == "abi":
                        interface_xml(candidate, key, decisions[bit])
                ET.ElementTree(candidate).write(bundle/f"{identity}.xml", encoding="utf-8")
            preview = rejected_preview()
        previews = [json.loads(line.removeprefix("VM argv ")) for line in preview.splitlines() if line.startswith("VM argv ")]
        assert len(previews) == 2
        for index, (identity, decision, argv) in enumerate(zip(("left", "right"), policies, previews, strict=True)):
            check_argv(argv, identity, decision, legacy[2] if optional else None)
            security = argv.index("--secure")
            run_index = argv.index("--run")
            # Review is a non-executing preview. Replay only the exact reviewed
            # interface arguments to measure the runtime boundary, without a
            # synthetic verifier or a permit to deploy these fixture images.
            observed = subprocess.run([runtime, *argv[:security], *argv[run_index:]], capture_output=True, text=True, timeout=30)
            diag = observed.stdout + observed.stderr
            actual = ("success" if observed.returncode == 0 else
                      "missing-provider" if "Missing module dependency" in diag else
                      "hidden" if "hidden" in diag or "namespace permission is disabled" in diag else
                      "unexpected")
            if actual != expected_class[index]:
                (out/"failure-review.log").write_text(log)
                (out/"failure-runtime.log").write_text(diag)
                raise RuntimeError(f"{test} {engine} {version} {identity} masks={masks} policies={policies}, expected {expected_class[index]} got {actual}")
            aggregates[f"{test}:{actual}"] += 1
            checked.append({"id": identity, "imports_mask": masks[index], "decision": decision,
                            "exit": observed.returncode, "result": actual, "module_sha256": digest(Path(argv[-1]))})
        outcomes.write(json.dumps({"phase": test, "engine": engine, "legacy": version, "vms": checked})+"\n")
        aggregates[f"{test}:paired-edit-reviews"] += 1

    def status_pair(engine, states):
        deployment = ET.Element("deployment", id="matrix-report")
        answers = []
        for identity, (interface, visible) in zip(("left", "right"), states, strict=True):
            wasm, signature = artifact(status_fixture(interface, visible))
            rec = ET.Element("recommendations")
            report_default = "deny" if interface == "allow" else "allow"
            visibility_default = "deny" if visible else "allow"
            interface_xml(rec, "permission.report", report_default)
            ET.SubElement(rec, "self-report", selector="preloaddl", access=visibility_default)
            operation = {"default": "remove", HIDDEN: "hide"}.get(interface, interface)
            answers += [
                report_default,
                visibility_default,
                f"{operation} permission.report",
                f"{'allow' if visible else 'deny'} report/preloaddl",
                "confirm",
            ]
            if interface == HIDDEN: answers.append("cancel")
            rights = f"{identity}-report.xml"
            ET.ElementTree(rec).write(bundle/rights, encoding="utf-8")
            ET.SubElement(deployment, "vm", {
                "id": identity, "engine": engine, "module": wasm.name, "sha256": signature,
                "policy": "review-preview.policy", "recommendations": rights,
                "memory-bytes": "134217728", "pids": "8",
            })
        ET.ElementTree(deployment).write(manifest, encoding="utf-8")
        code, log = terminal_run(list(map(str, review)), ("\n".join(answers)+"\n").encode())
        blocked = any(interface == HIDDEN for interface, _ in states)
        if (code != 0) != blocked or 'report/preloaddl' not in log or blocked and "STARTUP BLOCKED" not in log:
            (out/"failure-status-review.log").write_text(log)
            raise RuntimeError("read-only native status review failed")
        preview = log
        if blocked:
            for identity, (interface, visible) in zip(("left", "right"), states, strict=True):
                candidate = ET.Element("recommendations")
                if interface != "default": interface_xml(candidate, "permission.report", interface)
                ET.SubElement(candidate, "self-report", selector="preloaddl", access="allow" if visible else "deny")
                ET.ElementTree(candidate).write(bundle/f"{identity}-report.xml", encoding="utf-8")
            preview = rejected_preview()
        previews = [json.loads(line.removeprefix("VM argv ")) for line in preview.splitlines() if line.startswith("VM argv ")]
        checked = []
        for identity, (interface, visible), argv in zip(("left", "right"), states, previews, strict=True):
            assert "--wasm-register-dl" not in argv
            if interface == "default":
                assert "permission.report" not in [argv[i+2] for i, token in enumerate(argv) if token == "--ros-scene-interface"]
            else:
                offset = argv.index("--ros-scene-interface")
                assert argv[offset+1:offset+4] == [identity, "permission.report", interface]
            if not visible:
                offset = argv.index("--ros-scene")
                assert argv[offset+1:offset+5] == [identity, "permission.report", "preloaddl", "deny"]
            else:
                assert "--ros-scene" not in argv
            observed = subprocess.run([runtime, *argv[:argv.index("--secure")], *argv[argv.index("--run"):]],
                                      capture_output=True, text=True, timeout=30)
            if interface == HIDDEN:
                passed = observed.returncode != 0 and "interface is hidden" in (observed.stdout+observed.stderr)
            else:
                passed = observed.returncode == 0
            if not passed:
                (out/"failure-status-review.log").write_text(log)
                (out/"failure-status-runtime.log").write_text(observed.stdout+observed.stderr)
                raise RuntimeError(f"native status {identity} {interface} {visible} failed")
            checked.append({"id": identity, "interface": interface, "selector_visible": visible,
                            "module_sha256": digest(Path(argv[-1])), "exit": observed.returncode})
            aggregates["read-only-native-status:runtime-witnesses"] += 1
        outcomes.write(json.dumps({"phase": "read-only-native-status", "engine": engine, "vms": checked})+"\n")
        aggregates["read-only-native-status:paired-edit-reviews"] += 1

    for version, engine in product(("ros1", "ros2"), args.engines):
        for masks in product(range(16), repeat=2):
            decisions = []
            for index, mask in enumerate(masks):
                decided = []
                for bit in range(4):
                    enabled = mask & (1 << bit) and bit != 3 and (bit != 1 or version in args.legacy_abi)
                    decided.append(("allow" if index == 0 else "deny") if enabled else HIDDEN)
                decisions.append(tuple(decided))
            pair("all-four-family-presence-pairs", version, engine, masks, decisions)
        if version in args.legacy_abi or (not args.legacy_abi and version == "ros1"):
            available = range(3) if version in args.legacy_abi else (0, 2)
            options = []
            for states in product(("allow", "deny", HIDDEN), repeat=len(available)):
                current = [HIDDEN] * 4
                for bit, value in zip(available, states, strict=True):
                    current[bit] = value
                options.append(tuple(current))
            full = 7 if version in args.legacy_abi else 5
            for pair_of_decisions in product(options, repeat=2):
                pair("all-supported-policy-pairs", version, engine, (full, full), pair_of_decisions)

    for engine, states in product(args.engines,
                                  product(product(("allow", "deny", HIDDEN, "default"), (True, False)), repeat=2)):
        status_pair(engine, states)

    for flag in ("--wasm-register-dl", "-Wdl"):
        invalid = subprocess.run([deployer, "plan", manifest, "--policy-root", trust, flag, "unused"],
                                 capture_output=True, text=True, timeout=20)
        assert invalid.returncode != 0 and PRELOAD_REFUSED in invalid.stderr
        (out/f"raw-native-{flag.lstrip('-')}.log").write_text(invalid.stderr)
        aggregates["native-registration:raw-flag-rejected"] += 1

    # If an operator explicitly reviews a version query on a build that
    # lacks that legacy ABI, the actual runtime must still refuse to launch.
    optional_missing = set(("ros1", "ros2")) - set(args.legacy_abi)
    if optional_missing:
        # Protect the selected verifier input even if the compiler's original
        # executable was group-writable. The same bytes supply both witnesses.
        selected_runtime = out / "review-runtime"
        shutil.copyfile(runtime, selected_runtime)
        selected_runtime.chmod(0o755)
        assert digest(selected_runtime) == digest(runtime)
    for version in optional_missing:
        legacy_key = f"uwvm_{version}_v1.abi_version"
        legacy = (f"uwvm_{version}_v1", "abi_version", legacy_key)
        deployment = ET.Element("deployment", id=f"unsupported-{version}")
        rec = ET.Element("recommendations")
        interface_xml(rec, legacy_key, "allow")
        ET.ElementTree(rec).write(bundle/"missing-legacy.xml", encoding="utf-8")
        source = fixture((WASI, legacy, ROS_V2, NATIVE), 2, (HIDDEN, "allow", HIDDEN, HIDDEN))
        wasm, signature = artifact(source)
        ET.SubElement(deployment, "vm", {
            "id": "left", "engine": args.engines[0], "module": wasm.name, "sha256": signature,
            "policy": "review-preview.policy", "recommendations": "missing-legacy.xml",
            "memory-bytes": "134217728", "pids": "8",
        })
        ET.ElementTree(deployment).write(manifest, encoding="utf-8")
        code, log = terminal_run(list(map(str, adopt)), b"")
        assert code == 0 and "requires the separately compiled" in log
        blocked, reason = terminal_run([*map(str, adopt), "--runtime", str(selected_runtime)], b"")
        assert blocked != 0 and "selected VM build lacks the provider" in reason
        line, = [line for line in log.splitlines() if line.startswith("VM argv ")]
        argv = json.loads(line.removeprefix("VM argv "))
        check_argv(argv, "left", (HIDDEN, "allow", HIDDEN, HIDDEN), legacy_key)
        run = subprocess.run([runtime, *argv[:argv.index("--secure")], *argv[argv.index("--run"):]],
                             capture_output=True, text=True, timeout=30)
        assert run.returncode != 0 and f"invalid parameter: --{version}-single-create" in run.stderr
        (out/f"missing-{version}-after-explicit-approval.log").write_text(run.stderr)
        aggregates["legacy-explicit-edit:unsupported-build-refused"] += 1

    outcomes.close()
    (out/"results.json").write_text(json.dumps({
        "complete": True, "cgroup": str(group), "deployer_sha256": digest(deployer),
        "vm_sha256": digest(runtime), "legacy_abi": args.legacy_abi,
        "mask": {"1":"WASIp1 clock", "2":"named legacy ABI version", "4":"ROSv2 ABI",
                 "8":"unconfigured native-library import and denied policy edit"},
        "authority_scope": "exact argv replay of reviewed host permissions in two VM processes; signature and filesystem deployment are independently tested elsewhere",
        "totals": aggregates,
    }, indent=2)+"\n")


if __name__ == "__main__":
    main()
