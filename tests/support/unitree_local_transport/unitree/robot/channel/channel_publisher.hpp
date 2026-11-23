/** @file channel_publisher.hpp
 *  @brief Observe the original simulator publisher locally inside the managed driver.
 */
#pragma once
#include <unitree/common/thread/recurrent_thread.hpp>
#include <unitree/idl/go2/LowState_.hpp>
#include <cstdint>
#include <memory>
#include <string>

namespace unitree_simulator_output {
    void published(const std::string&, const unitree_go::msg::dds_::LowState_&);
    template<typename Message> void published(const std::string&, const Message&) {}
}

namespace unitree::robot {
template<typename Message> class ChannelPublisher {
public:
    explicit ChannelPublisher(const std::string& topic) : topic_(topic) {}
    void InitChannel() {}
    bool Write(const Message& value, std::int64_t = 0) {
        unitree_simulator_output::published(topic_, value);
        return true;
    }
private:
    std::string topic_;
};
template<typename Message> using ChannelPublisherPtr = std::shared_ptr<ChannelPublisher<Message>>;
}
