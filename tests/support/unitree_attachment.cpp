/** @file unitree_attachment.cpp
 *  @brief Serve read-only Go2 telemetry over authenticated local IPC.
 */
#include <uwvm2/imported/ros/scene/attachment_tls.h>
#include <uwvm2/imported/ros/scene/provider_bootstrap_receiver.h>

#include <unitree/idl/go2/LowState_.hpp>
#include <unitree/robot/channel/channel_subscriber.hpp>

#include <sys/socket.h>

#include <bit>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

#ifdef WROS_UNITREE_IN_PROCESS_SIMULATOR
void unitree_simulator_prepare();
bool unitree_simulator_next(std::uint64_t deadline, std::uint32_t& tick, float& position);
#endif

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

#ifdef WROS_UNITREE_IN_PROCESS_SIMULATOR
    constexpr std::uint64_t required_reads = 2;
    constexpr unsigned session_seconds = 90;

    std::optional<Snapshot> sample_go2(std::uint64_t deadline)
    {
        Snapshot value{};
        if (!unitree_simulator_next(deadline, value.tick, value.position))
            return std::nullopt;
        return value;
    }
#else
    constexpr std::uint64_t required_reads = 1;
    constexpr unsigned session_seconds = 10;
#ifdef WROS_UNITREE_RECORDED_SAMPLE
    // The independent simulator records one actual SDK sample before deployment.
    // The admitted adapter reads that immutable fixture and only uses the TLS carrier.
    std::optional<Snapshot> sample_go2(std::uint64_t deadline)
    {
        // Model a bounded sensor acquisition so the guest supervisor can inspect
        // the running processes. This fixture tests isolation, not sensor latency.
        auto const now = monotonic_ns();
        if (now >= deadline || deadline - now < UINT64_C(500000000))
            return std::nullopt;
        std::this_thread::sleep_for(500ms);
        // A normal UDP socket request must be denied in this managed driver.
        const int socket = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (socket >= 0)
        {
            ::close(socket);
            return std::nullopt;
        }
        if (errno != EPERM)
            return std::nullopt;
        std::puts("Managed driver endpoint creation denied");
        auto* input = std::fopen("/telemetry.txt", "r");
        if (!input)
            return std::nullopt;
        std::array<char, 128> text{};
        const auto size = std::fread(text.data(), 1, text.size(), input);
        const bool complete = !std::ferror(input) && std::feof(input);
        std::fclose(input);
        std::string_view remaining(text.data(), size);
        constexpr std::string_view prefix = "Go2 LowState tick=";
        constexpr std::string_view separator = " position=";
        if (!complete || !remaining.starts_with(prefix) || !remaining.ends_with('\n'))
            return std::nullopt;
        remaining.remove_prefix(prefix.size());
        remaining.remove_suffix(1);
        const auto split = remaining.find(separator);
        if (split == remaining.npos)
            return std::nullopt;
        const auto ticks = remaining.substr(0, split);
        const auto angle = remaining.substr(split + separator.size());
        Snapshot sample{};
        const auto time = std::from_chars(ticks.begin(), ticks.end(), sample.tick);
        const auto value = std::from_chars(angle.begin(), angle.end(), sample.position);
        if (time.ec != std::errc{} || time.ptr != ticks.end() ||
            value.ec != std::errc{} || value.ptr != angle.end() || !std::isfinite(sample.position))
            return std::nullopt;
        return sample;
    }
#else
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

#endif
#endif

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
        if (config.request_bytes < 24 || config.response_bytes < 24 ||
            config.request_bytes > protocol::maximum_payload || config.response_bytes > protocol::maximum_payload)
            return 11;
        auto const& binding = config.bound;
        scene::attachment_tls::channel channel;
        if (channel.bind(descriptors.carrier(), {config.peer.pid, config.peer.uid, config.peer.gid},
                         descriptors.identity(), scene::attachment_tls::purpose::driver,
                         binding.deployment, binding.vm, binding.module, binding.driver, binding.session,
                         binding.contract, protocol::header_bytes + std::max(config.request_bytes, config.response_bytes), true, descriptors.clock()) != Error::success)
            return 12;
        descriptors.reset();

        auto const until = std::min(monotonic_ns() + session_seconds * UINT64_C(1000000000), config.session_until_ns);
        std::vector<std::uint8_t> input(protocol::header_bytes + config.request_bytes);
        bool greeted{};
        std::uint64_t dispatched{};
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
            {
                if (!greeted || dispatched != required_reads)
                    return 15;
#ifdef WROS_UNITREE_IN_PROCESS_SIMULATOR
                std::puts("SENSOR_SESSION release reads=2");
#endif
                return 0;
            }
            if (message.type == protocol::kind::hello && !greeted)
            {
#ifdef WROS_UNITREE_IN_PROCESS_SIMULATOR
                unitree_simulator_prepare();
#endif
                greeted = true;
                message.type = protocol::kind::ready;
                if (reply(channel, message, {}, until) != Error::success)
                    return 16;
                continue;
            }

            auto const now = monotonic_ns();
            if (!greeted || dispatched >= required_reads || message.type != protocol::kind::request || message.sequence != dispatched + 1 ||
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
#ifdef WROS_UNITREE_IN_PROCESS_SIMULATOR
            scene::wire::reader encoded{wire.written()};
            std::uint64_t length{}, tick{}, bits{};
            if (!encoded.u64(length) || !encoded.u64(tick) || !encoded.u64(bits) || !encoded.done() || length != 16)
                return 19;
#endif
            scene::erase_bytes(body);
            if (sent != Error::success)
                return 19;
            std::printf("Go2 LowState over TLS tick=%u position=%.3f\n",
                        sample->tick, static_cast<double>(sample->position));
#ifdef WROS_UNITREE_IN_PROCESS_SIMULATOR
            std::printf("SENSOR_RESULT seq=%llu tick=%u position_bits=%08x\n",
                        static_cast<unsigned long long>(message.sequence), static_cast<unsigned>(tick), static_cast<unsigned>(bits));
#endif
            ++dispatched;
        }
        return 20;
    }
}

int receive_go2_attachment(char** argv)
{
    ::alarm(session_seconds + 5);
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
