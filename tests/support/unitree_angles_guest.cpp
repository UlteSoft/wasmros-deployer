/** @file unitree_angles_guest.cpp
 *  @brief Apply the ROS Noetic angles library to two authenticated Go2 samples in Wasm.
 */
#include <angles/angles.h>
#include <wros/scene.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace {
using Word = std::uint64_t;

template<class T> Word address(T* value) {
    return static_cast<Word>(reinterpret_cast<std::uintptr_t>(value));
}

void require(bool condition) {
    if (!condition) __builtin_trap();
}

template<class Operation> void wait_for(Operation operation) {
    for (unsigned attempt = 0; attempt < 4000000; ++attempt) {
        const auto status = operation();
        if (status == 0) return;
        require(status == 11);
    }
    __builtin_trap();
}

template<std::size_t N> Word capability(const char (&alias)[N]) {
    Word cap{};
    require(wr_capability_open(0, address(alias), N - 1, address(&cap)) == 0);
    return cap;
}

struct Clock {
    Word cap;
    Word handle;

    Word deadline() const {
        std::array<Word, 4> stamp{};
        Word size{};
        require(wr_clock_read(cap, 0, address(&handle), sizeof handle,
                              address(stamp.data()), sizeof stamp, address(&size)) == 0);
        require(size == sizeof stamp && stamp[2] == 1);
        return stamp[0] + 1500000000;
    }
};

Clock open_clock() {
    Clock clock{capability("steady"), 0};
    Word kind{}, size{};
    require(wr_clock_create(clock.cap, 0, address(&kind), sizeof kind,
                            address(&clock.handle), sizeof clock.handle, address(&size)) == 0);
    require(size == sizeof clock.handle);
    return clock;
}

struct Observation { Word tick; float position; };

Observation read_sample(Word cap, Word sequence, Clock clock) {
    std::array<Word, 6> request{sequence, clock.deadline(), 24, 1, 0, 16};
    std::array<Word, 130> reply{};
    Word size{};
    wait_for([&] {
        return wr_driver_submit(cap, 0, address(request.data()), sizeof request,
                                address(reply.data()), sizeof(Word), address(&size));
    });
    require(size == sizeof(Word) && reply[0] == sequence);

    Word capacity = 40;
    wait_for([&] {
        for (;;) {
            const auto status = wr_driver_result(cap, 0, address(&sequence), sizeof sequence,
                                                 address(reply.data()), capacity, address(&size));
            if (status != 90 || size <= capacity || size > sizeof reply) return status;
            capacity = size;
        }
    });
    require(size == 40 && reply[0] == 0 && reply[1] == 24 && reply[2] == 16);
    require(reply[3] > 0 && reply[3] <= UINT32_MAX && reply[4] <= UINT32_MAX);
    const auto bits = static_cast<std::uint32_t>(reply[4]);
    float q{};
    std::memcpy(&q, &bits, sizeof q);
    require(std::isfinite(q));
    return {reply[3], q};
}

/** @brief Compare the actual Noetic radian and degree functions with an independent reduction. */
void check_angle(double from, double to) {
    constexpr double pi = 3.141592653589793238462643383279502884;
    const double radians = angles::shortest_angular_distance(from, to);
    const double degrees = angles::to_degrees(radians);
    const double reduced = std::remainder((to - from) + pi, 2.0 * pi);
    const double expected = reduced <= 0.0 ? reduced + pi : reduced - pi;
    require(std::isfinite(radians) && radians > -pi && radians <= pi);
    require(std::fabs(radians - expected) < 2.0e-12);
    require(std::fabs(degrees * (pi / 180.0) - expected) < 2.0e-12);
}
}

/** @brief Obtain both samples and require increasing physics ticks before disconnecting. */
extern "C" void _start() {
    require(__builtin_wasm_memtag_status(0));
    const auto clock = open_clock();
    const auto cap = capability("go2-state");
    Word receipt{}, size{};
    wait_for([&] {
        return wr_driver_connect(cap, 0, 0, 0, address(&receipt), sizeof receipt, address(&size));
    });
    require(size == sizeof receipt && receipt == 1);
    const auto first = read_sample(cap, 1, clock);
    check_angle(4.0, first.position);
    const auto second = read_sample(cap, 2, clock);
    require(second.tick > first.tick);
    check_angle(first.position, second.position);
    require(wr_driver_disconnect(cap, 0, 0, 0, address(&receipt), sizeof receipt, address(&size)) == 0);
}
