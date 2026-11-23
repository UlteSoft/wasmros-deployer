/** @file unitree_live_simulator.cpp
 *  @brief Advance the pinned MuJoCo Go2 scene once per authenticated read.
 */
#include "unitree_sdk2_bridge.h"

#include <bit>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>

namespace {
using Clock = std::chrono::steady_clock;
struct Sample { std::uint32_t tick{}; float position{}; };
std::mutex sample_mutex;
std::condition_variable publication;
Sample published_sample;

class Simulator {
public:
    Simulator() {
        char error[512]{};
        model.reset(mj_loadXML("/simulator/scene.xml", nullptr, error, sizeof(error)));
        if (!model) throw std::runtime_error(std::string("loading the Go2 scene: ") + error);
        const int id = mj_name2id(model.get(), mjOBJ_SENSOR, "FR_hip_pos");
        if (model->nu != 12 || id < 0 || model->sensor_adr[id] != 0 || model->sensor_dim[id] != 1)
            throw std::runtime_error("unexpected Go2 sensor layout");
        data.reset(mj_makeData(model.get()));
        if (!data) throw std::runtime_error("MuJoCo data allocation failed");
        param::config.robot = "go2";
        param::config.use_joystick = 0;
        param::config.print_scene_information = 0;
        bridge = std::make_unique<Go2Bridge>(model.get(), data.get());
    }

    /** @brief Hold the new physics state until the upstream publisher delivers this tick. */
    bool next(std::uint64_t deadline, std::uint32_t& tick, float& position) {
        using namespace std::chrono;
        const Clock::time_point stop{nanoseconds(deadline)};
        if (Clock::now() >= stop) return false;
        mj_step(model.get(), data.get());
        const auto desired = static_cast<std::uint32_t>(std::llround(data->time * 1000));
        const auto sensor = static_cast<float>(data->sensordata[0]);
        if (!std::isfinite(sensor) || desired <= last_tick) return false;
        do {
            // The SDK publishing thread can still be handing off the previous tick.
            bridge->run();
            std::unique_lock lock(sample_mutex);
            if (publication.wait_until(lock, std::min(stop, Clock::now() + milliseconds(2)),
                                       [&] { return published_sample.tick == desired; })) {
                tick = published_sample.tick;
                position = published_sample.position;
                last_tick = tick;
                std::printf("MUJOCO_SOURCE tick=%u sensor_bits=%08x\n", desired,
                            std::bit_cast<std::uint32_t>(sensor));
                return std::bit_cast<std::uint32_t>(sensor) == std::bit_cast<std::uint32_t>(position);
            }
        } while (Clock::now() < stop);
        return false;
    }
private:
    std::unique_ptr<mjModel, decltype(&mj_deleteModel)> model{nullptr, mj_deleteModel};
    std::unique_ptr<mjData, decltype(&mj_deleteData)> data{nullptr, mj_deleteData};
    std::unique_ptr<Go2Bridge> bridge;
    std::uint32_t last_tick{};
};

Simulator& simulator() {
    static Simulator instance;
    return instance;
}
}

namespace unitree_simulator_output {
/** @brief Observe only the actual upstream LowState publisher's native output. */
void published(const std::string& topic, const unitree_go::msg::dds_::LowState_& value) {
    if (topic != "rt/lowstate") return;
    {
        std::lock_guard guard(sample_mutex);
        published_sample = {value.tick(), value.motor_state()[0].q()};
    }
    publication.notify_one();
}
}

/** @brief Load the protected scene before acknowledging the authenticated hello. */
void unitree_simulator_prepare() { (void)simulator(); }

bool unitree_simulator_next(std::uint64_t deadline, std::uint32_t& tick, float& position) {
    return simulator().next(deadline, tick, position);
}
