#!/usr/bin/env python3
"""@file vendor_unitree_mujoco.py
@brief Verify signed Go2 telemetry from the upstream headless simulator bridge.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

from qemu_supervisor import digest
from vendor_qualification import cgroup


BRIDGE_REVISION = "1eb6642e3f3fdfb7fb13a9794fd6a2dd93ea0e7d"
PYTHON_SDK_REVISION = "404fe44d76f705c002c97e773276f2a8fefb57e4"
PINNED_PYTHON_SDK = "19ed154137f8f4c7cdca0dc60c5d7d1d913e494f26939903c0b3addc4ee2059b"
PINNED_INPUTS = {
    "config.py": "9d14af3937cf0a842976d8c4c8c3158d6c8cdc70c588d3c2645ac4cbf82b6027",
    "unitree_sdk2py_bridge.py": "3ddb54ddddc6a20255e9bb77760537774b2eb77ce50073bf1f4a69bfaa77b599",
    "provenance.json": "b144a718c7bf567471e08cf08b4c45fea3e35e658e8b6f14839eca5df1bfbd03",
    "libunitree_sdk2.a": "b3f2dc5df8f1195b975854f44a260c205260479fc66923067b7c4098054d7588",
    "libddsc.so": "4038630c231412f7b34a2ea60df192bbdebd0a57f22ac7f35c1b6d28323e695c",
    "libddscxx.so": "d3e7c1b03123c2745839f2465041777ded090ad66d62f1372949209254f7ebe5",
}
REPLAY = r"""
    link=$(/usr/sbin/ip -o link show)
    test "$(printf '%s\n' "$link" | /usr/bin/wc -l)" -eq 1
    case "$link" in '1: lo: <LOOPBACK,UP,'*) ;; *) exit 1 ;; esac
    /usr/bin/openssl pkeyutl -verify -rawin -pubin -inkey native.pub -in native.sha256 -sigfile native.sig
    /usr/bin/sha256sum --quiet -c native.sha256
    ulimit -c 0
    "$1" -B "$2" simulate "$PWD" "$3" > simulator.log 2>&1 &
    simulation=$!
    "$1" -B "$2" read "$PWD" "$3" > sdk-python.log 2>&1 &
    reader=$!
    trap 'kill "$simulation" "$reader" 2>/dev/null || true' EXIT
    ./native-watch > sdk-cpp.log 2>&1
    wait "$reader"
    wait "$simulation"
    /usr/bin/grep -Fx OFFICIAL_BRIDGE_FINISHED simulator.log
    /usr/bin/grep -Fx OFFICIAL_LOWSTATE_AND_SPORT_MODE_STATE_OK sdk-python.log
    /usr/bin/grep -Fx NATIVE_GO2_LOWSTATE_AND_SPORT_MODE_STATE_OK sdk-cpp.log
"""


def require_digest(path, expected):
    """@brief Refuse inputs whose bytes differ from the selected upstream source."""
    if digest(path) != expected:
        raise ValueError(f"pinned input digest mismatch: {path}")


def execute(argv, out, logfile):
    """@brief Bound each preparation and replay step and retain its diagnostics."""
    with (out / logfile).open("ab") as log:
        return subprocess.run(list(map(str, argv)), cwd=out, timeout=60, check=True,
                              stdout=log, stderr=subprocess.STDOUT)


def sign(files, out):
    """@brief Sign an exact inventory without retaining the temporary private key."""
    manifest = out / "native.sha256"
    manifest.write_text("".join(f"{digest(path)}  {path}\n" for path in sorted(set(files))))
    with tempfile.TemporaryDirectory(dir=out) as scratch:
        key = Path(scratch) / "key"
        openssl = "/usr/bin/openssl"
        for args in ([openssl, "genpkey", "-algorithm", "ED25519", "-out", key],
                     [openssl, "pkey", "-in", key, "-pubout", "-out", "native.pub"],
                     [openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", manifest,
                      "-out", "native.sig"]):
            execute(args, out, "sign.log")


def main():
    """@brief Compile the C++ reader, sign the closure and compare two real SDK reads."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sdk-source", "python", "python-sdk-archive", "dependencies", "bridge", "model", "output"):
        parser.add_argument("--" + name, type=lambda value: Path(value).absolute(), required=True)
    args = parser.parse_args()
    group = cgroup()
    out = args.output.resolve()
    if ".tmp" not in out.parts or "\n" in str(out):
        parser.error("choose a fresh output directory in .tmp")
    os.umask(0o077)
    out.mkdir(mode=0o700)
    for name in ("TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME"):
        os.environ[name] = str(out)
    sdk, bridge, model = args.sdk_source.resolve(), args.bridge.resolve(), args.model.resolve()
    libraries = sdk / "thirdparty/lib/x86_64"
    archive = sdk / "lib/x86_64/libunitree_sdk2.a"
    provenance = model / "provenance.json"
    inputs = [bridge / "config.py", bridge / "unitree_sdk2py_bridge.py", provenance, archive,
              libraries / "libddsc.so", libraries / "libddscxx.so"]
    for path in inputs:
        require_digest(path, PINNED_INPUTS[path.name])
    model_record = json.loads(provenance.read_bytes())
    for relative, expected in model_record["files"].items():
        path = model / relative
        require_digest(path, expected)
        inputs.append(path)

    require_digest(args.python_sdk_archive, PINNED_PYTHON_SDK)
    source_folder = f"unitree_sdk2_python-{PYTHON_SDK_REVISION}"
    with tarfile.open(args.python_sdk_archive) as package:
        prefix = source_folder + "/unitree_sdk2py/"
        files = [file for file in package.getmembers() if file.isfile() and file.name.startswith(prefix)]
        package.extractall(out, members=files, filter="data")
    python_sdk = out / source_folder
    dependencies = args.dependencies.resolve()
    os.environ["PYTHONPATH"] = os.pathsep.join(map(str, (bridge, python_sdk, dependencies)))
    os.environ["LD_LIBRARY_PATH"] = str(libraries)
    os.environ["PYGAME_HIDE_SUPPORT_PROMPT"] = "1"
    support = Path(__file__).with_name("support").resolve()
    guest = support / "unitree_mujoco_bridge.py"
    cpp = support / "unitree_mujoco_dds.cpp"
    native = out / "native-watch"
    argv = ["/usr/bin/g++", "-std=c++17", "-O3", "-g", "-Wall", "-Wextra", "-Werror", "-pthread",
            "-isystem", sdk / "include", "-isystem", sdk / "thirdparty/include",
            "-isystem", sdk / "thirdparty/include/ddscxx", cpp, archive, "-L", libraries,
            "-lddscxx", "-lddsc", "-o", native]
    execute(argv, out, "build.log")
    inputs.extend([cpp, guest, native, args.python.resolve()])
    inputs.extend(path for tree in (python_sdk, dependencies) for path in tree.rglob("*") if path.is_file())
    if any("\n" in str(path) or "\\" in str(path) for path in inputs):
        raise ValueError("a test input path cannot be represented in the checksum manifest")
    sign(inputs, out)
    sandbox = ["/usr/bin/bwrap", "--die-with-parent", "--unshare-net", "--unshare-ipc",
               "--new-session", "--ro-bind", "/", "/", "--dev", "/dev", "--ro-bind", "/tmp", "/tmp",
               "--ro-bind", "/dev/shm", "/dev/shm", "--bind", out, out,
               "--", "/bin/sh", "-ec", REPLAY, "unitree-go2", args.python, guest, model / "scene.xml"]
    record = dict(complete=False, bridge_revision=BRIDGE_REVISION, python_sdk_revision=PYTHON_SDK_REVISION,
                  native_sdk_version="2.0.2", cgroup=str(group), argv=list(map(str, argv)),
                  manifest_sha256=digest(out / "native.sha256"), signature_sha256=digest(out / "native.sig"),
                  memory_events_before=(group / "memory.events").read_text())
    try:
        execute(sandbox, out, "replay.log")
        record["cases"] = ["official-go2-mujoco-bridge", "official-unitree-sdk-python-dds", "official-unitree-sdk-cpp-dds"]
        record["complete"] = True
    finally:
        record["memory_events_after"] = (group / "memory.events").read_text()
        record["logs"] = {name: digest(out / name) for name in
                          ("replay.log", "simulator.log", "sdk-python.log", "sdk-cpp.log") if (out / name).is_file()}
        (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Unitree Go2 headless simulator and both official SDK readers passed.")


if __name__ == "__main__":
    main()
