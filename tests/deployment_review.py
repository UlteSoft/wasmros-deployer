"""Exercise the real terminal assessment on a digest-bound, read-only fixture."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import time

sys.dont_write_bytecode = True
from vendor_qualification import qualification_environment


def terminal_run(command, answers, timeout=20):
    master, slave = pty.openpty()
    attributes = termios.tcgetattr(slave)
    attributes[1] &= ~termios.OPOST
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attributes)
    try:
        with subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave) as proc:
            os.close(slave)
            slave = None
            end = time.monotonic() + timeout
            output = bytearray()
            try:
                os.write(master, answers)
                while time.monotonic() < end and len(output) <= 1 << 20:
                    ready, _, _ = select.select([master], [], [], max(0, end-time.monotonic()))
                    if ready:
                        try:
                            data = os.read(master, 4096)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            data = b""
                        if not data:
                            return proc.wait(timeout=2), output.decode(errors="replace")
                        output.extend(data)
                raise TimeoutError("terminal review output or time exceeded")
            finally:
                if proc.poll() is None:
                    proc.kill()
    finally:
        os.close(master)
        if slave is not None:
            os.close(slave)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    group = qualification_environment(out)
    os.umask(0o077)
    out.mkdir(mode=0o700)
    bundle, trust = out / "bundle", out / "trust"
    bundle.mkdir()
    trust.mkdir()
    (trust/"staged.policy").write_text("preview only\n")
    (out/"guest.wat").write_text("""(module
        (import "wasi_snapshot_preview1" "clock_time_get" (func))
        (import "uwvm_ros_v2" "abi" (func))
        (import "peer" "provide" (func))
        (func (export "_start")))\n""")
    guest = bundle / "guest.wasm"
    subprocess.run(["/usr/bin/wat2wasm", out/"guest.wat", "-o", guest], check=True, timeout=20)
    digest = hashlib.sha256(guest.read_bytes()).hexdigest()
    (bundle/"rights.xml").write_text("""<recommendations>
        <interface name="control.submit" expose="allow"/>
        <interface name="wasip1.clock_time_get" expose="allow"/>
        <wasip1-clock name="monotonic-clock" access="allow"/>
        <interface name="context.open" expose="deny"/>
        </recommendations>\n""")
    manifest = bundle / "deployment.xml"
    driver = bundle / "preview.elf"
    driver.write_bytes(b"non-executed native risk preview")
    driver_digest = hashlib.sha256(driver.read_bytes()).hexdigest()
    manifest.write_text(f"""<deployment id="test">
        <vm id="a" module="guest.wasm" sha256="{digest}" policy="staged.policy" recommendations="rights.xml"
            cpus="0-2" memory-bytes="67108864" pids="8"/>
        <vm id="b" module="guest.wasm" sha256="{digest}" policy="staged.policy"
            cpus="2-3" memory-bytes="67108864" pids="8"/>
        <driver id="driver" file="preview.elf" sha256="{driver_digest}"
            vendor-version="preview" kind="executable" hardware-id="diagnostic-fixture" elf-signer="staged.policy">
          <attachment vm="a" alias="diagnostic" contract-sha256="{"1"*64}" sandbox="diagnostic"
             uid="14001" gid="14001" memory-bytes="67108864" pids="8" cpu-micros="100000"/>
        </driver>
        </deployment>\n""")
    command = [str(args.deployer.resolve()), "review", str(manifest),
               "--policy-root", str(trust), "--risk-report", "0"]
    pipe = subprocess.run(command, input="confirm\n", text=True, capture_output=True, timeout=10)
    (out/"nonterminal.log").write_text(pipe.stdout + pipe.stderr)
    assert pipe.returncode != 0 and "same terminal" in pipe.stderr
    hidden = None
    master, slave = pty.openpty()
    try:
        hidden = subprocess.run(command, stdin=slave, capture_output=True, text=True, timeout=10)
    finally:
        os.close(slave)
        os.close(master)
    assert hidden.returncode != 0 and "same terminal" in hidden.stderr
    status, log = terminal_run(command, b"cancel\n")
    (out/"cancelled.log").write_text(log)
    assert status != 0 and "operator cancelled review" in log and "VM argv" not in log
    status, log = terminal_run(command, b"deny\nallow\nallow\nallow\ndeny control.submit\nallow wasip1.sock_open\nshow\nconfirm\nallow clock.read\nconfirm\n")
    (out/"review.log").write_text(log)
    assert status == 0, log
    for line in ['VM "b" and "a" use overlapping CPUs', '0/10 (informational)', '9/10 (high)',
                 'UNASSESSED', 'enter a registered interface', 'imports "peer" "provide"',
                 'review effective decisions for VM "b"']:
        assert line.casefold() in log.casefold(), line
    previews = [json.loads(line.removeprefix("VM argv ")) for line in log.splitlines() if line.startswith("VM argv ")]
    assert len(previews) == 2
    for id_, argv in zip(("a", "b"), previews, strict=True):
        assert argv[argv.index("--wasm-set-main-module-name") + 1] == id_
        assert argv[argv.index("--debug-permissions") + 1] == "none"
        assert argv[argv.index("--debug-dump-force") + 1] == "none"
        assert not any(word.startswith(("--update-", "--diagnostic-control-", "--debug-jit-control-")) for word in argv)
        assert "wasip1.sock_open" not in argv
        if id_ == "a":
            assert argv[argv.index("control.submit") + 1] == "deny"
        else:
            assert argv[argv.index("clock.read") + 1] == "allow"
            assert "control.submit" not in argv
    preview = [str(args.deployer.resolve()), "plan", str(manifest), "--policy-root", str(trust)]
    cases = []
    for threshold in range(11):
        for spelling in (str(threshold), ">="+str(threshold)):
            run = subprocess.run([*preview, "--risk-report", spelling], capture_output=True, text=True, timeout=10)
            assert run.returncode == 0, run.stderr
            assert f"(threshold >={threshold}/10)" in run.stdout and "  UNASSESSED" in run.stdout
            for score in (0, 2, 4, 5, 7, 9):
                assert (f": {score}/10 (" in run.stdout) == (score >= threshold), (threshold, score)
            cases.append("threshold-"+spelling)
    default = subprocess.run(preview, capture_output=True, text=True, timeout=10)
    assert default.returncode == 0 and "(threshold >=5/10)" in default.stdout
    assert 'VM "b" and "a" use overlapping CPUs: 5/10 (moderate)' in default.stdout
    assert ": 7/10 (high)" in default.stdout and ": 9/10 (high)" in default.stdout
    assert ": 4/10 (" not in default.stdout and "  UNASSESSED" in default.stdout
    cases.append("default-includes-five-with-unassessed")
    for invalid in ("", "11", "-1", "00", "07", ">=11", ">", "NONE", "true", " 7"):
        run = subprocess.run([*preview, f"--risk-report={invalid}"], capture_output=True, text=True, timeout=10)
        assert run.returncode != 0 and "invalid --risk-report value" in run.stderr
    duplicate = subprocess.run([*preview, "--risk-report", "none", "--risk-report=7"],
                               capture_output=True, text=True, timeout=10)
    assert duplicate.returncode != 0 and "duplicate --risk-report" in duplicate.stderr
    cases += ["invalid-thresholds-refused", "duplicate-threshold-refused"]
    review = [str(args.deployer.resolve()), "review", str(manifest), "--policy-root", str(trust)]
    switch = "--accept-recommendations-through-risk"
    ceiling = "--risk-accept-threshold"
    for options in (["--accept-recommendations"], [switch], [ceiling, "default"],
                    [switch, ceiling, "11"], [switch, ceiling, "-1"], [switch, ceiling, "03"],
                    [switch, switch, ceiling, "3"], [switch, ceiling, "3", ceiling, "9"]):
        code, view = terminal_run([*review, *options], b"")
        assert code != 0 and "Adopted " not in view, options
    cases.append("retired-incomplete-or-invalid-adoption-options-refused")
    adopt = [*review, switch, ceiling, "9"]
    for label, setting, threshold in (("default", None, 5), ("explicit-seven", ">=7", 7), ("none", "none", None)):
        argv = adopt if setting is None else [*adopt, f"--risk-report={setting}"]
        code, view = terminal_run(argv, b"")
        (out/f"adopt-{label}.log").write_text(view)
        assert code == 0 and "at or below 9/10" in view and "[recommended" not in view and " edits [" not in view
        assert ("Risk report" in view) == (threshold is not None)
        assert ("  UNASSESSED" in view) == (threshold is not None)
        assert "Review effective decisions for VM" in view and 'allow "control.submit"' in view
        assert 'default read-only self observation via "permission.report"' in view
        if threshold is None:
            assert "/10 (" not in view
        else:
            assert f"(threshold >={threshold}/10)" in view
            assert (": 5/10 (moderate)" in view) == (threshold == 5)
            assert ": 9/10 (high)" in view and ": 7/10 (high)" in view
        cases.append("one-click-"+label)
    for selected in ("default", "3"):
        for display in ("none", "10", "0"):
            code, view = terminal_run([*review, switch, ceiling, selected, "--risk-report", display], b"deny\nconfirm\n")
            assert code == 0 and "at or below 3/10" in view
            assert view.count("[recommended") == 1 and '"control.submit" [recommended allow]' in view
            assert 'Adopted deny "context.open"' in view and 'Adopted allow "wasip1.clock_time_get"' in view
            assert ('Risk report' in view) == (display != "none")
            runs = [json.loads(row.removeprefix("VM argv ")) for row in view.splitlines() if row.startswith("VM argv ")]
            assert runs[0][runs[0].index("control.submit") + 1] == "deny"
    cases.append("default-three-and-explicit-three-require-the-same-individual-decisions-at-every-display-threshold")
    rights_path = bundle/"rights.xml"
    original = rights_path.read_text()
    for forbidden in ("deployer.control", "vm.debug", "vm.dump", "vm.update", "driver.direct-connect"):
        rights_path.write_text(f'<recommendations><interface name="{forbidden}" expose="allow"/></recommendations>')
        code, view = terminal_run([*review, switch, ceiling, "10", "--risk-report=none"], b"")
        assert code != 0 and "invalid interface" in view and "VM argv" not in view, forbidden
    rights_path.write_text(original)
    for flag in ("--debug-jit-control-fd", "--diagnostic-control-fd", "--update-control-fd", "--ros-scene-driver-channel"):
        code, view = terminal_run([*review, switch, ceiling, "10", flag, "3"], b"")
        assert code != 0 and "VM argv" not in view, flag
    cases.append("direct-workload-management-and-peer-endpoints-rejected-even-at-ten")
    for namespace, name in (("uwvm_ros_v2", "vm.debug"), ("uwvm_update", "publish"),
                            ("wros_deployer", "control"), ("wasi_snapshot_preview1", "sock_send")):
        wat = out/"forbidden.wat"
        image = bundle/"forbidden.wasm"
        wat.write_text(f'(module (import "{namespace}" "{name}" (func)))')
        subprocess.run(["/usr/bin/wat2wasm", wat, "-o", image], check=True, timeout=15)
        digest_forbidden = hashlib.sha256(image.read_bytes()).hexdigest()
        check = bundle/"forbidden.xml"
        check.write_text(f'<deployment id="test"><vm id="probe" module="forbidden.wasm" sha256="{digest_forbidden}" policy="staged.policy" memory-bytes="67108864" pids="8"/></deployment>')
        code, view = terminal_run([review[0], "review", str(check), "--policy-root", str(trust),
                                   switch, ceiling, "10", "--risk-report=none"], b"")
        assert code != 0 and "forbidden workload host import" in view and "VM argv" not in view
    cases.append("forbidden-static-host-imports-refused-before-human-or-threshold-decisions")
    for desired, command in (("hidden", "hide abi"), ("deny", "deny abi"), (None, "hide abi\nremove abi")):
        rights_path.write_text('<recommendations><interface name="abi" expose="allow"/></recommendations>')
        code, view = terminal_run(review, ("allow\n"+command+"\nconfirm\nconfirm\n").encode())
        vms = [json.loads(row.removeprefix("VM argv ")) for row in view.splitlines() if row.startswith("VM argv ")]
        assert code == 0 and vms and "default read-only ABI version" in view
        if desired is None:
            assert "abi" not in vms[0]
        else:
            assert vms[0][vms[0].index("abi")+1] == desired
    rights_path.write_text(original)
    cases.append("explicit-ABI-hiding-denial-and-removal-to-default")
    withheld = subprocess.run([*preview, "--risk-report=none", "--wasm-register-dl", "ignored"],
                              capture_output=True, text=True, timeout=10)
    assert withheld.returncode != 0 and "(10/10 high risk)" in withheld.stderr
    cases.append("reject-native-even-with-summary-none")
    (out/"results.json").write_text(json.dumps({
        "cgroup": str(group), "module_sha256": digest,
        "deployer_sha256": hashlib.sha256(args.deployer.read_bytes()).hexdigest(),
        "cases": ["nonterminal-refused", "hidden-output-refused", "cancelled",
                  "edited-and-confirmed", "cross-vm-placement", "exact-declared-imports", "unregistered-edit-refused", *cases],
        "complete": True,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
