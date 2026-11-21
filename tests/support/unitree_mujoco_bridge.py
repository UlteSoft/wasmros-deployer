"""@file unitree_mujoco_bridge.py
@brief Exercise Unitree's original Python DDS bridge with headless MuJoCo.
"""

import math
from pathlib import Path
import sys
import threading
import time
from xml.sax.saxutils import escape

import config
import mujoco
from unitree_sdk2py.core import channel
from unitree_sdk2py.idl.unitree_go.msg.dds_ import LowState_, SportModeState_
from unitree_sdk2py_bridge import UnitreeSdk2Bridge


def simulation(scene):
    """@brief Advance the official Go2 scene and publish a known joint observation."""
    model = mujoco.MjModel.from_xml_path(scene)
    data = mujoco.MjData(model)
    for _ in range(150):
        mujoco.mj_step(model, data)
    if model.nu != 12 or data.time < 0.12:
        raise ValueError("unexpected Go2 model or simulation timestep")
    joint = model.joint("FR_hip_joint").id
    data.qpos[model.jnt_qposadr[joint]] = 0.125
    mujoco.mj_forward(model, data)
    if data.sensordata[0] != 0.125:
        raise ValueError("the original first joint sensor did not report the reference position")
    bridge = UnitreeSdk2Bridge(model, data)
    print(f"PHYSICS_READY t={data.time:.6f} joint0={data.sensordata[0]:.3f}", flush=True)
    time.sleep(8)
    if not bridge.have_frame_sensor_:
        raise ValueError("Go2's frame sensor was not discovered by the upstream bridge")
    print("OFFICIAL_BRIDGE_FINISHED", flush=True)


def read():
    """@brief Verify joint position, IMU and high-level pose in a separate SDK process."""
    low_seen, high_seen = threading.Event(), threading.Event()

    def low(message):
        quaternion = message.imu_state.quaternion
        if (message.motor_state[0].q == 0.125 and len(quaternion) == 4
                and abs(math.sqrt(sum(v * v for v in quaternion)) - 1.0) < 0.01):
            low_seen.set()

    def high(message):
        if len(message.position) == 3 and all(map(math.isfinite, message.position)) and message.position[2] > 0:
            high_seen.set()

    low_subscriber = channel.ChannelSubscriber("rt/lowstate", LowState_)
    high_subscriber = channel.ChannelSubscriber("rt/sportmodestate", SportModeState_)
    low_subscriber.Init(low, 1)
    high_subscriber.Init(high, 1)
    if not low_seen.wait(6) or not high_seen.wait(2):
        raise RuntimeError("Go2 LowState and SportModeState were not both observed")
    print("OFFICIAL_LOWSTATE_AND_SPORT_MODE_STATE_OK", flush=True)


def main():
    """@brief Configure the same loopback-only DDS domain as the native subscriber."""
    mode, output, scene = sys.argv[1:]
    if mode not in ("simulate", "read"):
        raise ValueError("expected simulate or read")
    config.USE_JOYSTICK = 0
    trace = Path(output) / ("cyclonedds-" + mode + ".log")
    # The upstream SDK hardcodes a tracing destination under /tmp. Set the
    # destination in the per-process configuration before constructing Domain.
    channel.ChannelConfigHasInterface = channel.ChannelConfigHasInterface.replace(
        "/tmp/cdds.LOG", escape(str(trace)))
    channel.ChannelFactoryInitialize(74, "lo")
    if mode == "simulate":
        simulation(scene)
    else:
        read()


if __name__ == "__main__":
    main()
