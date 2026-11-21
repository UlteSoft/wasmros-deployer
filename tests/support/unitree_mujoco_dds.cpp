/** @file unitree_mujoco_dds.cpp
 *  @brief Read joint position, IMU and base pose through the original Unitree SDK.
 */
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <thread>
#include <unitree/idl/go2/LowState_.hpp>
#include <unitree/idl/go2/SportModeState_.hpp>
#include <unitree/robot/channel/channel_subscriber.hpp>

int main()
{
    using namespace std::chrono_literals;
    using LowState = unitree_go::msg::dds_::LowState_;
    using SportModeState = unitree_go::msg::dds_::SportModeState_;

    std::atomic<bool> have_joint{}, have_pose{};
    unitree::robot::ChannelFactory::Instance()->Init(74, "lo");
    unitree::robot::ChannelSubscriber<LowState> joints("rt/lowstate");
    unitree::robot::ChannelSubscriber<SportModeState> pose("rt/sportmodestate");
    joints.InitChannel([&](void const* data) {
        auto const& state = *static_cast<LowState const*>(data);
        float squared_norm{};
        for (float value : state.imu_state().quaternion())
            squared_norm += value * value;
        if (state.motor_state()[0].q() == 0.125f && std::abs(squared_norm - 1.0f) < 0.02f)
            have_joint.store(true, std::memory_order_relaxed);
    }, 1);
    pose.InitChannel([&](void const* data) {
        auto const& state = *static_cast<SportModeState const*>(data);
        auto const& position = state.position();
        if (std::isfinite(position[0]) && std::isfinite(position[1]) &&
            std::isfinite(position[2]) && position[2] > 0.0f)
            have_pose.store(true, std::memory_order_relaxed);
    }, 1);

    auto const deadline = std::chrono::steady_clock::now() + 6s;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (have_joint.load(std::memory_order_relaxed) && have_pose.load(std::memory_order_relaxed))
        {
            std::puts("NATIVE_GO2_LOWSTATE_AND_SPORT_MODE_STATE_OK");
            return 0;
        }
        std::this_thread::sleep_for(5ms);
    }
    return 1;
}
