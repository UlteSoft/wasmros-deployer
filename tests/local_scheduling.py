"""Build a signed core-Wasm scheduling probe using the VM's ABI fixture."""
import re
import sys
import xml.etree.ElementTree as ET


def create(vm_source, out, cosign, ca, check, stamp):
    sys.path.insert(0, str(vm_source / "test/0084.ros-runtime"))
    try:
        from run_scene_vm import Guest
    finally:
        sys.path.pop(0)
    contract = (vm_source / "src/uwvm2/imported/ros/runtime/contract.h").read_text()
    ops = [dict(name=name, words=int(words), bytes=int(size)) for name, words, size in
           re.findall(r' X\(\w+,"([^"]+)","[^"]+",(\d+),(-?\d+)\)', contract)]
    assert len(ops) == 16
    guest = Guest(ops)
    xml = ET.Element("recommendations")
    for name in ["abi", "capability.open", "capability.close", *[r["name"] for r in ops]]:
        ET.SubElement(xml, "interface", name=name, expose="allow")

    def resource(alias, kind, actions, decision="allow"):
        for operation in actions.split():
            ET.SubElement(xml, "local-resource", type=kind, alias=alias, operation=operation, access=decision)

    resource("signal", "guard", "guard.create guard.trigger")
    resource("signal", "guard", "guard.take", "deny")
    resource("sibling", "guard", "guard.trigger")
    resource("hidden", "guard", "guard.create", "deny")
    resource("sim", "clock.ros", "clock.create clock.update clock.read")
    for alias, kind in (("steady", "clock.steady"), ("system", "clock.system")):
        resource(alias, kind, "clock.create clock.read")
    resource("alarm", "timer", "timer.create timer.reset timer.take")
    resource("waiter", "wait", "wait.create resource.close")
    guest.open("hidden", 13)
    guest.open("absent", 13)
    cap = {alias: guest.open(alias) for alias in ("signal", "sibling", "sim", "steady", "system", "alarm", "waiter")}
    guest.call("guard.create", cap["signal"])
    guard = guest.save("local_guard")
    guest.call("guard.trigger", cap["signal"], [guard])
    guest.call("guard.take", cap["signal"], [guard], expected=13)
    guest.call("guard.trigger", cap["sibling"], [guard], expected=9)
    for alias, number in (("steady", 0), ("system", 1), ("sim", 2)):
        guest.call("clock.create", cap[alias], [number])
        clock = guest.save("clock_"+alias)
        guest.call("clock.read", cap[alias], [clock])
        guest.equal(guest.word(536), number)
    guest.call("clock.update", cap["sim"], [cap["sim"], clock, 100, 1])
    guest.call("timer.create", cap["alarm"], [cap["sim"], clock])
    timer = guest.save("local_timer")
    guest.call("timer.reset", cap["alarm"], [timer, 105, 10])
    guest.call("timer.take", cap["alarm"], [timer], expected=11)
    guest.call("clock.update", cap["sim"], [cap["sim"], clock, 125, 1])
    guest.call("timer.take", cap["alarm"], [timer])
    guest.equal(guest.word(512), 105)
    guest.equal(guest.word(520), 125)
    guest.equal(guest.word(528), 3)
    guest.call("wait.create", cap["waiter"])
    wait = guest.save("local_wait")
    guest.call("resource.close", cap["waiter"], [wait])
    guest.call("resource.close", cap["waiter"], [wait], expected=9)
    bundle = out / "bundle"
    assembly = out / "schedule.wat"
    assembly.write_text(guest.render())
    ET.indent(xml)
    (bundle / "schedule-rights.xml").write_bytes(ET.tostring(xml))
    app = out / "schedule.wasm"
    check("assemble-scheduling", ["wat2wasm", "--enable-multi-memory", assembly, "-o", app], True)
    policy = out / "policies/schedule.policy"
    check("schedule-policy", [cosign, "wasm", "secure", "policy-init", "--output", policy,
          "--state-dir", out / "schedule-state", "--trust-root", ca["root"], "--certificate",
          ca["certificate"], "--module-id", "schedule", "--algorithms", "Ed25519", "--capabilities", "32"], True)
    check("sign-scheduling", [cosign, "wasm", "secure", "sign", app, "--policy", policy, "--key", ca["key"],
          "--certificate", ca["certificate"], "--crl", ca["crl"], "--module-id", "schedule", "--module-version", "1",
          "--algorithm", "Ed25519", "--capabilities", "32", "--not-before", stamp(-60), "--not-after", stamp(3600),
          "--output", bundle / "schedule.signed.wasm"], True)
