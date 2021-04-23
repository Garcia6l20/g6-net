#pragma once

#include <unifex/coroutine.hpp>

#include <atomic>
#include <optional>

namespace g6 {
    using unifex::coro::coroutine_handle;

    template<typename Ref>
    class async_event
    {

        using underlying_value_type = std::remove_cvref_t<Ref>;
        using value_type = std::conditional_t<std::is_reference_v<Ref>, std::reference_wrapper<underlying_value_type>,
                                              underlying_value_type>;

        struct wait_operation {
            async_event &event_;
            explicit wait_operation(async_event &event) noexcept : event_{event} {}
            wait_operation(wait_operation &&) = delete;
            wait_operation(wait_operation const &) = delete;

            bool await_ready() {
                return false;
            }

            auto await_suspend(coroutine_handle<> awaiter) noexcept {
                awaiter_ = awaiter;
                void *old_state = event_.state_.load(std::memory_order_acquire);
                do {
                    if (old_state != nullptr) {
                        // event is already awaited, push on queue
                        auto *current = static_cast<wait_operation *>(old_state);
                        while (current->next_ != nullptr) { current = current->next_; }
                        current->next_ = this;
                        return true;
                    }
                } while (!event_.state_.compare_exchange_strong(old_state, static_cast<void *>(this),
                                                                std::memory_order_release, std::memory_order_acquire));
                return true;
            }

            decltype(auto) await_resume() {
                if constexpr (std::is_reference_v<Ref>) {
                    return event_.value_.value().get();
                } else {
                    return event_.value_.value();
                }
            }

            coroutine_handle<> awaiter_{};
            wait_operation *next_ = nullptr;
        };

    public:
        auto operator co_await() noexcept { return wait_operation{*this}; }

        size_t publish(value_type &&value) noexcept {
            void *old_state = state_.exchange(nullptr, std::memory_order_acq_rel);
            if (old_state != nullptr) {
                value_.template emplace(std::forward<value_type>(value));
                auto *current = static_cast<wait_operation *>(old_state);
                size_t resumed_count = 0;
                while (current != nullptr) {
                    auto *next = current->next_;
                    current->awaiter_.resume();
                    ++resumed_count;
                    current = next;
                }
                return resumed_count;
            } else {
                return 0;
            }
        }

        friend auto &operator<<(async_event& event, value_type&& value) noexcept {
            event.publish(std::forward<value_type>(value));
            return event;
        }

    private:
        std::atomic<void *> state_{nullptr};
        std::optional<value_type> value_{};
    };
}// namespace g6
