/** @file unitree_low_state.cpp
 *  @brief Exchange a known Go2 LowState sample using Unitree's native SDK.
 */
#include <unitree/idl/go2/LowState_.hpp>
#include <unitree/robot/channel/channel_publisher.hpp>
#include <unitree/robot/channel/channel_subscriber.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string_view>
#include <thread>

#ifdef WROS_UNITREE_ATTACHMENT
int receive_go2_attachment(char** argv);
#endif

namespace
{
    using Sample = unitree_go::msg::dds_::LowState_;
    using namespace std::chrono_literals;
    constexpr char topic[] = "rt/lowstate";
    constexpr std::uint32_t tick = 41347;
    constexpr float position = 0.125f;

    int publish()
    {
        unitree::robot::ChannelPublisher<Sample> publisher(topic);
        publisher.InitChannel();
        Sample sample{};
        sample.tick(tick);
        sample.motor_state()[0].q(position);
        unsigned transmitted{};
        auto const until = std::chrono::steady_clock::now() + 6s;
        while (std::chrono::steady_clock::now() < until)
        {
            transmitted += publisher.Write(sample);
            std::this_thread::sleep_for(50ms);
        }
        return transmitted ? 0 : 1;
    }

    int read()
    {
        std::atomic<bool> seen{};
        unitree::robot::ChannelSubscriber<Sample> subscriber(topic);
        subscriber.InitChannel([&](void const* data) {
            auto const& sample = *static_cast<Sample const*>(data);
            if (sample.tick() == tick && sample.motor_state()[0].q() == position)
                seen.store(true, std::memory_order_relaxed);
        }, 1);
        auto const until = std::chrono::steady_clock::now() + 9s;
        while (!seen.load(std::memory_order_relaxed) && std::chrono::steady_clock::now() < until)
            std::this_thread::sleep_for(10ms);
        subscriber.CloseChannel();
        if (!seen.load(std::memory_order_relaxed))
            return 1;
        std::printf("Go2 LowState tick=%u position=%.3f\n", tick, static_cast<double>(position));
        return 0;
    }
}

int main(int argc, char** argv)
{
#ifdef WROS_UNITREE_ATTACHMENT
    if (argc == 6)
        return receive_go2_attachment(argv);
#endif
    if (argc != 2)
        return 2;
    auto const mode = std::string_view(argv[1]);
    if (mode != "publish" && mode != "read")
        return 2;
    unitree::robot::ChannelFactory::Instance()->Init(74, "lo");
    return mode == "publish" ? publish() : read();
}
