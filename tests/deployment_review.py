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
import termios
import time


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
    assert ".tmp" in out.parts
    group = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().removeprefix("0::/")
    assert (group/"memory.max").read_text().strip() == "68719476736"
    assert (group/"memory.swap.max").read_text().strip() == "0"
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
    manifest.write_text(f"""<deployment id="test">
        <vm id="a" module="guest.wasm" sha256="{digest}" policy="staged.policy" recommendations="rights.xml"
            cpus="0-2" memory-bytes="67108864" pids="8"/>
        <vm id="b" module="guest.wasm" sha256="{digest}" policy="staged.policy"
            cpus="2-3" memory-bytes="67108864" pids="8"/>
        </deployment>\n""")
    command = [str(args.deployer.resolve()), "review", str(manifest),
               "--policy-root", str(trust), "--accept-recommendations"]
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
    status, log = terminal_run(command, b"deny control.submit\nallow wasip1.sock_open\nshow\nconfirm\nallow clock.read\nconfirm\n")
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
        assert "wasip1.sock_open" not in argv
        if id_ == "a":
            assert argv[argv.index("control.submit") + 1] == "deny"
        else:
            assert argv[argv.index("clock.read") + 1] == "allow"
            assert "control.submit" not in argv
    (out/"results.json").write_text(json.dumps({
        "cgroup": str(group), "module_sha256": digest,
        "deployer_sha256": hashlib.sha256(args.deployer.read_bytes()).hexdigest(),
        "cases": ["nonterminal-refused", "hidden-output-refused", "cancelled",
                  "edited-and-confirmed", "cross-vm-placement", "exact-declared-imports", "unregistered-edit-refused"],
        "complete": True,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
