"""Exercise the public offline recovery inspector and compare MVP guests with WABT."""
import argparse
import hashlib
import json
import os
import resource
from pathlib import Path
import subprocess


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployer", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    assert out.is_relative_to(root / ".tmp")
    group = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().split("0::/", 1)[1]
    assert group == Path("/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    assert (group / "memory.max").read_text().strip() == "68719476736"
    assert (group / "memory.swap.max").read_text().strip() == "0"
    assert os.sched_getaffinity(0) <= {4, 5, 6, 7}
    out.mkdir(parents=True, exist_ok=False)
    deployer = args.deployer.resolve()
    wat, validate, interp = map(Path, ("/usr/bin/wat2wasm", "/usr/bin/wasm-validate", "/usr/bin/wasm-interp"))
    features = ["--disable-" + name for name in (
        "mutable-globals", "saturating-float-to-int", "sign-extension", "simd",
        "multi-value", "bulk-memory", "reference-types")]
    report = {"complete": False, "cgroup": str(group), "inputs": {
        str(p): digest(p) for p in (deployer, wat, validate, interp, Path(__file__).resolve())}, "cases": []}

    def save():
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(argv, expected):
        env = {**os.environ, "TMPDIR": str(out)}
        proc = subprocess.run(argv, cwd=out, env=env, capture_output=True, text=True, timeout=10)
        if (proc.returncode == 0) != expected:
            raise RuntimeError(f"{argv}: exit {proc.returncode}: {proc.stdout} {proc.stderr}")
        return proc.stdout + proc.stderr

    def check(name, contents, accepted, *, wabt_run=False, wabt_valid=None):
        binary = out / (name + ".wasm")
        if isinstance(contents, bytes):
            binary.write_bytes(contents)
        else:
            text = binary.with_suffix(".wat")
            text.write_text("(module " + contents + ")\n")
            run([wat, "--enable-all", "--no-check", text, "-o", binary], True)
        answer = run([deployer, "inspect-recovery", binary], accepted)
        if accepted:
            assert digest(binary) in answer and "Host imports 0." in answer
        if wabt_valid is not None:
            run([validate, *features, binary], wabt_valid)
        if wabt_run:
            actual = run([interp, *features, "--run-all-exports", binary], True)
            assert "error" not in actual.lower() and "trap" not in actual.lower(), actual
        report["cases"].append(dict(name=name, sha256=digest(binary), admitted=accepted,
                                    upstream_validation=wabt_valid, upstream_execution=wabt_run,
                                    message=answer.strip()))
        save()
        return binary

    entry = '(func (export "_start") nop)'
    mem = "(memory 1 2)"
    core = mem + entry
    valid = check("entry-export", core, True, wabt_run=True, wabt_valid=True)
    check("entry-section", mem + "(func $start i32.const 4 i32.const 7 i32.store) (start $start)",
          True, wabt_run=True, wabt_valid=True)
    check("mvp-bounded-table", "(table 1 2 funcref)" + core, True, wabt_run=True, wabt_valid=True)
    check("memory-at-limit", "(memory 16 16)" + entry, True, wabt_run=True, wabt_valid=True)
    body = ("(memory 1 2) (global $g (mut i32) (i32.const 1)) "
            '(func (export "_start") i32.const 8 global.get $g i32.store '
            "i32.const 8 i32.load i32.const 1 i32.ne if unreachable end)")
    check("private-load-store", body, True, wabt_run=True, wabt_valid=True)

    for name, string in {
        "wasi-import": '(import "wasi_snapshot_preview1" "clock_time_get" (func))' + core,
        "unapproved-recovery-abi": '(import "wros_recovery" "restart" (func))' + core,
        "foreign-wasm": '(import "robot" "status" (func))' + core,
        "imported-memory": '(import "env" "memory" (memory 1 2))' + entry,
        "wrong-entry-type": mem + '(func (export "_start") (result i32) i32.const 0)',
        "wrong-entry-name": mem + '(func (export "other"))',
        "shared-entry": mem + '(func $s (export "_start")) (start $s)',
        "entry-with-extra-export": core + '(export "memory" (memory 0))',
        "missing-entry": mem, "missing-memory": entry,
        "unbounded-memory": "(memory 1)" + entry, "oversize-memory": "(memory 0 17)" + entry,
        "unbounded-table": "(table 1 funcref)" + core, "oversize-table": "(table 0 257 funcref)" + core,
        "local-budget": mem + '(func (export "_start") (local ' + 'i32 ' * 257 + '))',
        "control-budget": mem + '(func (export "_start") ' + 'block ' * 65 + 'end ' * 65 + ')',
        "instruction-budget": mem + '(func (export "_start") ' + 'nop ' * 8192 + ')',
    }.items():
        check(name, string, False, wabt_valid=True)
    for name, string in {
        "shared-memory": "(memory 1 2 shared)" + entry, "memory64": "(memory i64 1 2)" + entry,
        "two-memories": mem + core, "eh": "(tag (param i32))" + core,
        "sign-extension": mem + '(func (export "_start") i32.const 1 i32.extend8_s drop)',
        "typed-stack-invalid": mem + '(func (export "_start") i64.const 0 i32.eqz drop)',
        "bulk-memory": mem + '(func (export "_start") i32.const 0 i32.const 0 i32.const 0 memory.fill)',
        "simd": mem + '(func (export "_start") v128.const i32x4 0 1 2 3 drop)',
        "multi-value": '(type (func (result i32 i32)))' + core,
    }.items():
        check(name, string, False, wabt_valid=False)
    raw = valid.read_bytes()
    check("component", b"\0asm\x0d\0\x01\0", False)
    check("overlong-module", bytes(65537), False)
    check("truncated-code", raw[:-1], False, wabt_valid=False)
    check("trailing-section", raw + b"\xff", False, wabt_valid=False)
    custom = b"component-type:probe"
    payload = bytes([len(custom)]) + custom
    check("component-metadata", raw + bytes([0, len(payload)]) + payload, False)
    alias = out / "linked.wasm"
    alias.symlink_to(valid.name)
    fifo = out / "pipe"
    os.mkfifo(fifo)
    for label, path in (("symlink", alias), ("fifo", fifo), ("directory", out)):
        message = run([deployer, "inspect-recovery", path], False)
        report["cases"].append(dict(name=label, admitted=False, message=message.strip()))
    # A valid module can still trap; inspection must never execute it.
    trap = check("well-typed-trap", mem + '(func (export "_start") unreachable)', True, wabt_valid=True)
    executed = run([interp, *features, "--run-all-exports", trap], True)
    assert "unreachable" in executed.lower()
    report["wabt_trap_control"] = executed.strip()
    loop = check("well-typed-loop", mem + '(func (export "_start") loop br 0 end)',
                 True, wabt_valid=True)
    try:
        subprocess.run([interp, *features, "--run-all-exports", loop], cwd=out, capture_output=True,
                       timeout=0.5, check=False)
    except subprocess.TimeoutExpired:
        # subprocess.run kills and waits for its child on timeout. This bound
        # belongs to the test process and conveys no supervisor authority.
        report["wabt_loop_test_timeout_ms"] = 500
    else:
        raise AssertionError("interpreter returned from an unconditional loop")
    report["complete"] = True
    save()
    print(f"PASS {len(report['cases'])} recovery preflight cases")


if __name__ == "__main__":
    main()
