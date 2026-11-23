/** @file channel_subscriber.hpp
 *  @brief Leave the simulation command subscriber disconnected.
 */
#pragma once
#include <functional>
#include <memory>
#include <string>

namespace unitree::robot {
template<typename Message> class ChannelSubscriber {
public:
    explicit ChannelSubscriber(const std::string& topic) : topic_(topic) {}
    void InitChannel(const std::function<void(const void*)>&) {}
    const std::string& GetChannelName() const { return topic_; }
private:
    std::string topic_;
};
template<typename Message> using ChannelSubscriberPtr = std::shared_ptr<ChannelSubscriber<Message>>;
}
