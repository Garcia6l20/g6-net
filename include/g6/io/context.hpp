#ifndef G6_IO_CONTEXT_HPP_
#define G6_IO_CONTEXT_HPP_

#include <g6/io/config.hpp>

#include <span>

#if G6_IO_USE_IO_URING_CONTEXT
#include <liburing.h>
#include <unifex/linux/io_uring_context.hpp>
#elif G6_IO_USE_EPOLL_CONTEXT

#include <sys/socket.h>
#include <unifex/linux/io_epoll_context.hpp>

#elif G6_IO_USE_IOCP_CONTEXT
#include <unifex/win32/low_latency_iocp_context.hpp>
#else
#error "Cannot find suitable IO context"
#endif

#include <unifex/scheduler_concepts.hpp>
#include <unifex/tag_invoke.hpp>

#include <spdlog/spdlog.h>

namespace g6 {
    using namespace unifex;

#if G6_OS_LINUX
    using namespace unifex::linuxos;
#elif G6_OS_WINDOWS
    using namespace unifex::win32;
#endif
}// namespace g6


#define G6_IO_SET_VALUE(__receiver, ...)                                                                               \
    if constexpr (noexcept(unifex::set_value(std::move(__receiver), __VA_ARGS__))) {                                   \
        g6::set_value(std::move(__receiver), __VA_ARGS__);                                                             \
    } else {                                                                                                           \
        UNIFEX_TRY { g6::set_value(std::move(__receiver), __VA_ARGS__); }                                              \
        UNIFEX_CATCH(...) { unifex::set_error(std::move(__receiver), std::current_exception()); }                      \
    }

namespace g6::io {
    namespace detail {
#if G6_IO_USE_IO_URING_CONTEXT
        using underlying_context = io_uring_context;
#elif G6_IO_USE_EPOLL_CONTEXT
        using underlying_context = io_epoll_context;
#elif G6_IO_USE_IOCP_CONTEXT
        using underlying_context = low_latency_iocp_context;
#endif
    }// namespace detail
    class context : public detail::underlying_context
    {
    public:
        using underlying_context = detail::underlying_context;
        using underlying_context::underlying_context;

        class scheduler : public detail::underlying_context::scheduler
        {
        public:
            explicit scheduler(io::context &ctx, detail::underlying_context::scheduler sched)
                : context_{ctx}, detail::underlying_context::scheduler{sched} {}

            [[nodiscard]] auto &get_context() const { return context_; }

        private:
            io::context &context_;
        };

        inline auto get_scheduler() noexcept { return scheduler{*this, detail::underlying_context::get_scheduler()}; }

        friend auto tag_invoke(tag_t<unifex::get_scheduler>, io::context &ctx) noexcept { return ctx.get_scheduler(); }

    public:
        template<auto op_code, typename Receiver, template<class> typename Operation>
        struct io_operation_base : completion_base {
            static constexpr bool is_stop_ever_possible = !is_stop_never_possible_v<stop_token_type_t<Receiver>>;

            template<typename Sender>
            explicit io_operation_base(Sender &sender, Receiver &&r) noexcept
                : context_{sender.context_}, fd_{sender.fd_}, receiver_{(Receiver &&) r},
                  can_be_cancelled_{get_stop_token(r).stop_possible()} {}

            void start() noexcept {
                if (!context_.is_running_on_io_thread()) {
                    this->execute_ = &on_schedule_complete;
                    context_.schedule_remote(this);
                } else {
                    start_io();
                }
            }

            static void on_schedule_complete(operation_base *op) noexcept {
                static_cast<io_operation_base *>(op)->start_io();
            }

            static auto &get_impl(operation_base *op) noexcept { return *static_cast<Operation<Receiver> *>(op); }

            void request_stop() noexcept {
                stop_callback_.destruct();
                if (context_.is_running_on_io_thread()) {
                    request_stop_local();
                } else {
                    request_stop_remote();
                }
            }

            enum class state
            {
                none = 0,
                pending = 0b01,
                cancel_pending = 0b10
            };
            std::atomic<state> state_;

            struct cancel_callback {
                io_operation_base &op_;

                void operator()() noexcept { op_.request_stop(); }
            };

            manual_lifetime<typename stop_token_type_t<Receiver>::template callback_type<cancel_callback>>
                stop_callback_{};

            bool can_be_cancelled_;

            void request_stop_local() noexcept {
                assert(context_.is_running_on_io_thread());

                this->execute_ = &io_operation_base::cleanup_and_complete_with_done;

                auto state = this->state_.load(std::memory_order_relaxed);
                if (state == state::pending) {
                    context_.schedule_local(this);
                } else {
                    // Timer already elapsed and added to ready-to-run queue.
                }
            }

            static void complete_with_done(operation_base *op) noexcept {
                // Avoid instantiating set_done() if we're not going to call it.
                if constexpr (is_stop_ever_possible) {
                    auto &self = get_impl(op);
                    unifex::set_done(std::move(self).receiver_);
                } else {
                    // This should never be called if stop is not possible.
                    assert(false);
                }
            }

            void request_stop_remote() noexcept {
                auto oldState = this->state_.load(std::memory_order_relaxed);
                if (oldState == state::pending) {
                    // Timer had not yet elapsed.
                    // We are responsible for scheduling the completion of this timer
                    // operation.
                    this->execute_ = &io_operation_base::cleanup_and_complete_with_done;
                    this->context_.schedule_remote(this);
                }
            }

            static void cleanup_and_complete_with_done(operation_base *op) noexcept {
                // Avoid instantiating set_done() if we're never going to call it.
                if constexpr (is_stop_ever_possible) {
                    auto &self = get_impl(op);
                    assert(self.context_.is_running_on_io_thread());

                    auto state = self.state_.load(std::memory_order_relaxed);
                    if (state == state::pending) {
                        // Timer not yet removed from the timers_ list. Do that now.

                        auto populateSqe = [self = &self](io_uring_sqe &sqe) mutable noexcept {
                            const auto [data, len, off] = self->get_io_data();

                            sqe.opcode = IORING_OP_ASYNC_CANCEL;
                            sqe.flags = 0;
                            sqe.ioprio = 0;
                            sqe.fd = -1;
                            sqe.off = 0;
                            sqe.addr = reinterpret_cast<std::uintptr_t>(data);
                            sqe.len = 0;
                            sqe.cancel_flags = 0;

                            spdlog::info("cancel pending...");
                            self->state_.store(state::cancel_pending, std::memory_order_acq_rel);

                            sqe.user_data = reinterpret_cast<std::uintptr_t>(static_cast<io_operation_base *>(self));
                            self->execute_ = &io_operation_base::complete_with_done;
                        };

                        if (!self.context_.try_submit_io(populateSqe)) {
                            self.execute_ = &io_operation_base::cleanup_and_complete_with_done;
                            self.context_.schedule_pending_io(&self);
                        }
                    }

                    unifex::set_done(std::move(self).receiver_);
                } else {
                    // Should never be called if stop is not possible.
                    assert(false);
                }
            }

            auto &get_impl() noexcept { return get_impl(this); }

            void start_io() noexcept {
                assert(context_.is_running_on_io_thread());
                auto populateSqe = [this](io_uring_sqe &sqe) noexcept {
                    const auto [data, len, off] = get_impl().get_io_data();

                    sqe.opcode = op_code;
                    sqe.flags = 0;
                    sqe.ioprio = 0;
                    sqe.fd = fd_;
                    sqe.off = off;
                    sqe.addr = reinterpret_cast<std::uintptr_t>(data);
                    sqe.len = len;
                    sqe.rw_flags = 0;
                    sqe.user_data = reinterpret_cast<std::uintptr_t>(static_cast<io_operation_base *>(this));
                    sqe.__pad2[0] = sqe.__pad2[1] = sqe.__pad2[2] = 0;

                    this->execute_ = &io_operation_base::on_operation_complete;

                    this->state_.store(state::pending, std::memory_order_acq_rel);

                    if constexpr (is_stop_ever_possible) {
                        stop_callback_.construct(get_stop_token(receiver_), cancel_callback{*this});
                    }
                };

                if (!context_.try_submit_io(populateSqe)) {
                    this->execute_ = &io_operation_base::on_schedule_complete;
                    context_.schedule_pending_io(this);
                }
            }

            const struct set_result_ {
                template<typename... Ts>
                void operator()(Ts &&...result) const noexcept {
                    if constexpr (noexcept(unifex::set_value(std::move(receiver_),
                                                             std::forward<decltype(result)>(result)...))) {
                        unifex::set_value(std::move(receiver_), std::forward<decltype(result)>(result)...);
                    } else {
                        UNIFEX_TRY {
                            unifex::set_value(std::move(receiver_), std::forward<decltype(result)>(result)...);
                        }
                        UNIFEX_CATCH(...) { unifex::set_error(std::move(receiver_), std::current_exception()); }
                    }
                }
//                template<typename... Ts>
//                void operator()(std::tuple<Ts...> &&result) const noexcept {
//                    std::apply(*this, std::forward<decltype(result)>(result));
//                }
                Receiver &receiver_;
            } set_result{receiver_};

            static void on_operation_complete(operation_base *op) noexcept {
                auto &self = get_impl(op);
                self.stop_callback_.destruct();
                if (self.result_ >= 0) {
                    self.set_result(self.get_result());
                } else if (self.result_ == -ECANCELED) {
                    unifex::set_done(std::move(self.receiver_));
                } else {
                    unifex::set_error(std::move(self.receiver_),
                                      std::error_code{-self.result_, std::system_category()});
                }
            }

            context &context_;
            int fd_;
            Receiver receiver_;
        };


        class base_sender;
    };

    class context::base_sender
    {
        using offset_t = std::int64_t;

        template<auto, typename, template<class> typename>
        friend class io_operation_base;

    public:
        // Produces number of bytes read.
        template<template<typename...> class Variant, template<typename...> class Tuple>
        using value_types = Variant<Tuple<size_t>>;

        // Note: Only case it might complete with exception_ptr is if the
        // receiver's set_value() exits with an exception.
        template<template<typename...> class Variant>
        using error_types = Variant<std::error_code, std::exception_ptr>;

        static constexpr bool sends_done = true;

        explicit base_sender(context &context, int fd) noexcept : context_(context), fd_(fd) {}
        base_sender(base_sender &&) = default;
        base_sender(base_sender const &) = delete;

    protected:
        context &context_;
        int fd_;
    };
}// namespace g6::io

#endif// G6_IO_CONTEXT_HPP_
