/** @file unitree_attachment.cpp
 *  @brief Serve one read-only Go2 telemetry snapshot over authenticated local IPC.
 */
#include <uwvm2/imported/ros/scene/attachment_tls.h>
#include <uwvm2/imported/ros/scene/provider_bootstrap_receiver.h>

#include <unitree/idl/go2/LowState_.hpp>
#include <unitree/robot/channel/channel_subscriber.hpp>

#include <bit>
#include <charconv>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>

namespace
{
    namespace scene = uwvm2::imported::ros::scene;
    namespace bootstrap = scene::provider_bootstrap;
    namespace protocol = scene::drivers::protocol;
    using Error = scene::drivers::error;
    using Sample = unitree_go::msg::dds_::LowState_;
    using namespace std::chrono_literals;

    std::uint64_t monotonic_ns()
    {
        timespec stamp{};
        if (::clock_gettime(CLOCK_MONOTONIC, &stamp) != 0)
            std::terminate();
        return static_cast<std::uint64_t>(stamp.tv_sec) * 1000000000 + stamp.tv_nsec;
    }

    struct Snapshot
    {
        std::uint32_t tick;
        float position;
    };

    std::optional<Snapshot> sample_go2(std::uint64_t deadline)
    {
        unitree::robot::ChannelFactory::Instance()->Init(74, "lo");
        std::optional<Snapshot> recorded;
        std::mutex lock;
        unitree::robot::ChannelSubscriber<Sample> subscriber("rt/lowstate");
        subscriber.InitChannel([&](void const* data) {
            auto const& sample = *static_cast<Sample const*>(data);
            float const position = sample.motor_state()[0].q();
            if (std::isfinite(position))
            {
                std::lock_guard guard(lock);
                recorded = Snapshot{sample.tick(), position};
            }
        }, 1);
        while (monotonic_ns() < deadline)
        {
            {
                std::lock_guard guard(lock);
                if (recorded)
                    return recorded;
            }
            std::this_thread::sleep_for(1ms);
        }
        return std::nullopt;
    }

    bool allowed_read(scene::wire::bytes body)
    {
        scene::wire::reader input{body};
        std::uint64_t handle{}, offset{}, size{};
        return input.u64(handle) && handle == 1 && input.u64(offset) && offset == 0 &&
               input.u64(size) && size == 16 && input.done();
    }

    Error reply(scene::attachment_tls::channel& channel, protocol::header const& message,
                scene::wire::bytes payload, std::uint64_t until)
    {
        std::array<std::uint8_t, protocol::header_bytes> header{};
        if (!protocol::encode(message, payload.size(), header))
            return Error::invalid;
        for (;;)
        {
            auto const status = channel.send(header, payload);
            if (status != Error::again || monotonic_ns() >= until)
                return status;
            std::this_thread::sleep_for(100us);
        }
    }

    int serve(int courier, bootstrap::credentials origin, std::string_view mode)
    {
        bootstrap::descriptors descriptors;
        bootstrap::record config{};
        if (bootstrap::receive(courier, origin, UINT64_C(5000000000), descriptors, config) !=
            bootstrap::receive_status::success)
            return 10;
        ::close(courier);
        if (config.request_bytes != 32 || config.response_bytes != 32)
            return 11;
        auto const& binding = config.bound;
        scene::attachment_tls::channel channel;
        if (channel.bind(descriptors.carrier(), {config.peer.pid, config.peer.uid, config.peer.gid},
                         descriptors.identity(), scene::attachment_tls::purpose::driver,
                         binding.deployment, binding.vm, binding.module, binding.driver, binding.session,
                         binding.contract, protocol::header_bytes + 32, true, descriptors.clock()) != Error::success)
            return 12;
        descriptors.reset();

        auto const until = std::min(monotonic_ns() + UINT64_C(10000000000), config.session_until_ns);
        std::array<std::uint8_t, protocol::header_bytes + 32> input{};
        bool greeted{};
        bool dispatched{};
        while (monotonic_ns() < until)
        {
            std::size_t size{};
            auto const status = channel.receive(input, size);
            if (status == Error::again)
            {
                std::this_thread::sleep_for(100us);
                continue;
            }
            if (status != Error::success)
            {
                if (mode == "wrong-key" && !greeted && status == Error::denied)
                    std::puts("CASE unitree-attachment-authentication-denied PASS");
                return 13;
            }

            protocol::header message{};
            scene::wire::bytes payload;
            if (!protocol::decode(std::span{input}.first(size), message, payload) || message.bound != binding)
                return 14;
            if (message.type == protocol::kind::release)
                return greeted && dispatched ? 0 : 15;
            if (message.type == protocol::kind::hello && !greeted)
            {
                greeted = true;
                message.type = protocol::kind::ready;
                if (reply(channel, message, {}, until) != Error::success)
                    return 16;
                continue;
            }

            auto const now = monotonic_ns();
            if (!greeted || dispatched || message.type != protocol::kind::request || message.sequence != 1 ||
                message.deadline <= now || message.deadline > config.session_until_ns ||
                message.deadline - now > config.request_ns || !allowed_read(payload))
                return 17;
            scene::erase_bytes(std::span{input}.first(size));
            auto const sample = sample_go2(std::min(until, message.deadline));
            if (!sample)
                return 18;
            std::array<std::uint8_t, 24> body{};
            scene::wire::writer wire{body};
            wire.u64(16);
            wire.u64(sample->tick);
            wire.u64(std::bit_cast<std::uint32_t>(sample->position));
            message.type = protocol::kind::result;
            auto const sent = reply(channel, message, wire.written(), until);
            scene::erase_bytes(body);
            if (sent != Error::success)
                return 19;
            std::printf("Go2 LowState over TLS tick=%u position=%.3f\n",
                        sample->tick, static_cast<double>(sample->position));
            dispatched = true;
        }
        return 20;
    }
}

int receive_go2_attachment(char** argv)
{
    ::alarm(15);
    std::array<std::uint32_t, 4> fields{};
    for (std::size_t i{}; i < fields.size(); ++i)
    {
        std::string_view argument(argv[i + 1]);
        auto const end = argument.data() + argument.size();
        auto const result = std::from_chars(argument.data(), end, fields[i]);
        if (result.ec != std::errc{} || result.ptr != end)
            return 2;
    }
    if (fields[0] > INT_MAX)
        return 2;
    return serve(static_cast<int>(fields[0]), {fields[1], fields[2], fields[3]}, argv[5]);
}
