#!/usr/bin/env python3
"""@file vendor_universal_robots.py
@brief Replay signed Universal Robots Client Library tests in a private network namespace.
"""

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

from qemu_supervisor import digest
from vendor_qualification import cgroup


URCL_SHA256 = "d30c9f4137a314e05c5f304140f53cc30a0b428f3d5d7acf1acb40ce76ca532e"
GTEST_SHA256 = "65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c"
TEST_REGEX = r"^(RTDEClientFakeServerTest|RTDEBackgroundReadTest|rtde_parser)[.]"
OFFLINE_RUN = r"""
    links=$(/usr/sbin/ip -o link show)
    test "$(printf '%s\n' "$links" | /usr/bin/wc -l)" -eq 1
    case "$links" in '1: lo: <LOOPBACK,UP,'*) ;; *) exit 1 ;; esac
    /usr/bin/openssl pkeyutl -verify -rawin -pubin -inkey native.pub -in native.sha256 -sigfile native.sig >/dev/null
    /usr/bin/sha256sum --quiet -c native.sha256
    exec /usr/bin/ctest --test-dir build --timeout 40 --output-on-failure \
        --no-tests=error --output-junit "$2" --tests-from-file "$1"
"""


def unpack(archive, expected_digest, output):
    """@brief Verify an upstream archive before extracting its single source tree."""
    if digest(archive) != expected_digest:
        raise ValueError(f"archive digest mismatch: {archive}")
    with tarfile.open(archive) as package:
        package.extractall(output, filter="data")
    source, = output.iterdir()
    return source


def run(argv, output, log, timeout):
    """@brief Execute one preparation or replay step with a bounded wall time."""
    with (output / log).open("ab") as transcript:
        command = list(map(str, argv))
        return subprocess.run(command, cwd=output, check=True, timeout=timeout,
                              stdout=transcript, stderr=subprocess.STDOUT)


def sign_artifacts(output, paths):
    """@brief Sign the exact CTest executables, runtime libraries and test configuration."""
    inventory = {str(path.relative_to(output)): digest(path) for path in paths}
    data = "".join(f"{value}  {name}\n" for name, value in sorted(inventory.items()))
    (output / "native.sha256").write_text(data)
    (output / "altered.sha256").write_text(data + "# changed manifest\n")
    with tempfile.TemporaryDirectory(dir=output) as scratch:
        key = Path(scratch) / "fixture.key"
        openssl = "/usr/bin/openssl"
        run([openssl, "genpkey", "-algorithm", "ED25519", "-out", key], output, "sign.log", 20)
        run([openssl, "pkey", "-in", key, "-pubout", "-out", "native.pub"], output, "sign.log", 20)
        run([openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", "native.sha256",
             "-out", "native.sig"], output, "sign.log", 20)
    verify = [openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", "native.pub"]
    run([*verify, "-in", "native.sha256", "-sigfile", "native.sig"], output, "sign.log", 20)
    with (output / "sign.log").open("ab") as log:
        altered = subprocess.run([*verify, "-in", "altered.sha256", "-sigfile", "native.sig"],
                                 cwd=output, stdout=log, stderr=subprocess.STDOUT, timeout=20)
    if altered.returncode != 1:
        raise ValueError("OpenSSL did not reject the modified manifest")
    return inventory


def select_tests(build, out, suite):
    """@brief Group upstream CTest cases so each executable gets a fresh network namespace."""
    groups = defaultdict(list)
    exact = subprocess.check_output(
        ["/usr/bin/ctest", "--test-dir", build, "--show-only=json-v1", "-R",
         ".*" if suite == "offline" else TEST_REGEX], cwd=out, timeout=30)
    (out / "expected.json").write_bytes(exact)
    for case in json.loads(exact)["tests"]:
        command = case.get("command", [])
        executable = Path(command[0]).resolve(strict=True) if command else None
        if executable is None or executable.parent != build / "tests":
            raise ValueError(f"unexpected CTest executable for {case['name']}")
        groups[executable].append(case["name"])
    if not groups:
        raise ValueError("no built upstream CTest cases selected")
    return groups


def main():
    """@brief Build unmodified official tests and execute them with loopback only."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "gtest-archive", "output"):
        parser.add_argument("--" + name, type=lambda path: Path(path).resolve(), required=True)
    parser.add_argument("--suite", choices=("offline", "rtde"), default="offline")
    args = parser.parse_args()
    group = cgroup()
    out = args.output
    if ".tmp" not in out.parts:
        parser.error("choose a fresh build directory under .tmp")
    os.umask(0o077)
    out.mkdir(mode=0o700)
    for variable in ("TMPDIR", "TMP", "TEMP"):
        os.environ[variable] = str(out)

    urcl = unpack(args.archive, URCL_SHA256, out / "urcl")
    gtest = unpack(args.gtest_archive, GTEST_SHA256, out / "gtest")
    build = out / "build"
    configure = ["/usr/bin/cmake", "-S", urcl, "-B", build, "-G", "Ninja",
                 "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-O3 -g1 -DNDEBUG",
                 "-DCMAKE_CXX_COMPILER=/usr/bin/g++", "-DBUILDING_TESTS=ON", "-DINTEGRATION_TESTS=OFF",
                 "-DCHECK_RTDE_DOCS_RECIPE=OFF", "-DFETCHCONTENT_FULLY_DISCONNECTED=ON",
                 f"-DFETCHCONTENT_SOURCE_DIR_GOOGLETEST={gtest}"]
    targets = ("tests/all",) if args.suite == "offline" else ("rtde_client_fake_server_tests", "rtde_parser_tests")
    compile_tests = ["/usr/bin/cmake", "--build", build, "--parallel", "3", "--target", *targets]
    run(configure, out, "configure.log", 60)
    run(compile_tests, out, "build.log", 720)

    groups = select_tests(build, out, args.suite)
    for binary, names in groups.items():
        (out / (binary.name + ".tests")).write_text("\n".join(names) + "\n")
    files = [build / "liburcl.so", *sorted((build / "lib").glob("*.so*")),
             *groups, *sorted(out.glob("*.tests")), out / "expected.json",
             *sorted(build.rglob("CTestTestfile.cmake"))]
    inventory = sign_artifacts(out, files)
    replay = ["/usr/bin/bwrap", "--die-with-parent", "--unshare-net", "--ro-bind", "/", "/",
              "--dev-bind", "/dev", "/dev", "--ro-bind", "/tmp", "/tmp",
              "--ro-bind", "/dev/shm", "/dev/shm", "--bind", out, out, "--",
              "/bin/sh", "-ec", OFFLINE_RUN, "urcl-offline"]
    record = {
        "complete": False, "urcl_release": "2.16.0", "urcl_archive_sha256": URCL_SHA256,
        "suite": args.suite,
        "gtest_release": "1.17.0", "gtest_archive_sha256": GTEST_SHA256,
        "cgroup": str(group), "events_before": (group / "memory.events").read_text(),
        "build_commands": [list(map(str, argv)) for argv in (configure, compile_tests)],
        "native_artifacts": inventory, "native_signature_sha256": digest(out / "native.sig"),
        "signer_sha256": digest(out / "native.pub"), "altered_manifest_rejected": True,
        "executables": [],
    }
    receipt = out / "results.json"
    try:
        record["cases"] = []
        for binary, names in groups.items():
            junit = out / (binary.name + ".junit.xml")
            status = 0
            try:
                run([*replay, out / (binary.name + ".tests"), junit], out, "ctest.log", 180)
            except subprocess.CalledProcessError as failure:
                status = failure.returncode
            cases = ET.parse(junit).getroot().findall(".//testcase") if junit.exists() else []
            record["cases"].extend(dict(case.attrib, passed=case.get("status") == "run"
                                        and case.find("failure") is None and case.find("skipped") is None)
                                   for case in cases)
            actual = [case.attrib["name"] for case in cases]
            record["executables"].append(dict(name=binary.name, expected=len(names), actual=len(actual),
                                               matching_tests=sorted(actual) == sorted(names), exit=status))
        record["inputs_unchanged"] = all(digest(out / name) == value for name, value in inventory.items())
        record["complete"] = (all(row["exit"] == 0 and row["matching_tests"] for row in record["executables"])
                              and all(case["passed"] for case in record["cases"])
                              and record["inputs_unchanged"])
    finally:
        record["events_after"] = (group / "memory.events").read_text()
        receipt.write_text(json.dumps(record, indent=2) + "\n")
    if not record["complete"]:
        raise SystemExit(f"incomplete Universal Robots qualification: {receipt}")
    print(f"Universal Robots Client Library: {len(record['cases'])} official tests passed")


if __name__ == "__main__":
    main()
