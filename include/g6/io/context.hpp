#pragma once

#include <g6/io/config.hpp>

#include <span>

#if G6_IO_USE_IO_URING_CONTEXT
#include <liburing.h>
#include <unifex/linux/io_uring_context.hpp>
#elif G6_IO_USE_EPOLL_CONTEXT

#include <unifex/linux/io_epoll_context.hpp>
#include <sys/socket.h>

#elif G6_IO_USE_IOCP_CONTEXT
#include <unifex/win32/low_latency_iocp_context.hpp>
#else
#error "Cannot find suitable IO context"
#endif

namespace g6 {
    using namespace unifex;
#if G6_OS_LINUX
    using namespace unifex::linuxos;
#elif G6_OS_WINDOWS
    using namespace unifex::win32;
#endif
}// namespace g6

namespace g6::io {
    namespace detail {
        enum class io_operation_id {
            readv, writev, send, recv, sendmsg, recvmsg, connect, accept
        };
#if G6_IO_USE_IO_URING_CONTEXT
        using underlying_context = io_uring_context;
        template <io_operation_id op_id>
        consteval auto io_uring_op_code() noexcept {
            constexpr uint8_t io_uring_ops[] = {
                    IORING_OP_READV, IORING_OP_WRITEV, IORING_OP_SEND, IORING_OP_RECV, IORING_OP_SENDMSG,
                    IORING_OP_RECVMSG, IORING_OP_CONNECT, IORING_OP_ACCEPT
            };
            return io_uring_ops[static_cast<int>(op_id)];
        }

#elif G6_IO_USE_EPOLL_CONTEXT
        using underlying_context = io_epoll_context;
#elif G6_IO_USE_IOCP_CONTEXT
        using underlying_context = low_latency_iocp_context;
#endif
    }
    class context : public detail::underlying_context {
    public:
        using detail::underlying_context::underlying_context;

        class scheduler : public detail::underlying_context::scheduler {
        public:
            explicit scheduler(io::context &ctx, detail::underlying_context::scheduler sched) : context_{ctx},
                                                                                                detail::underlying_context::scheduler{
                                                                                                        sched} {}

            [[nodiscard]] auto &get_context() const { return context_; }

        private:
            io::context &context_;
        };

        inline auto get_scheduler() noexcept {
            return scheduler{*this, detail::underlying_context::get_scheduler()};
        }

        friend auto tag_invoke(tag_t<unifex::get_scheduler>, io::context &ctx) noexcept {
            return ctx.get_scheduler();
        }

    public:
        template<detail::io_operation_id op_code, typename Receiver, typename CRTP = void>
        class base_operation;

        class base_sender;
    };

    template<detail::io_operation_id op_code, typename Receiver, typename CRTP>
    class context::base_operation : protected completion_base {
        friend detail::underlying_context;
        friend completion_base;
    public:
        template<typename Receiver2>
        explicit base_operation(const auto &sender, Receiver2 &&r)
                : context_(sender.context_),
                  fd_(sender.fd_),
                  receiver_((Receiver2 &&) r) {
        }
        template<typename Receiver2>
        explicit base_operation(io::context &ctx, int fd, Receiver2 &&r)
            : context_(ctx),
              fd_(fd),
              receiver_((Receiver2 &&) r) {
        }
        base_operation(base_operation &&) = delete;
        base_operation(base_operation const&) = delete;
        ~base_operation() = default;

        void start() noexcept {
            if (!context_.is_running_on_io_thread()) {
                this->execute_ = &on_schedule_complete;
                context_.schedule_remote(this);
            } else {
                start_io();
            }
        }

    private:
        static constexpr bool is_stop_ever_possible =
                !is_stop_never_possible_v<stop_token_type_t<Receiver>>;

        static auto &get_impl(operation_base *op) noexcept {
            if constexpr (not std::is_void_v<CRTP>) {
                return *static_cast<CRTP *>(op);
            } else {
                return *static_cast<base_operation *>(op);
            }
        }

        auto &get_impl() noexcept {
            return get_impl(this);
        }

        static void on_schedule_complete(operation_base *op) noexcept {
            static_cast<base_operation *>(op)->start_io();
        }

        void start_io() noexcept {
            assert(context_.is_running_on_io_thread());
#if G6_IO_USE_IO_URING_CONTEXT
            auto populateSqe = [this](io_uring_sqe &sqe) noexcept {
                const auto[data, len, off] = get_impl().get_io_data();
                io_uring_prep_rw(detail::io_uring_op_code<op_code>(), &sqe, fd_, data, len, off);
                sqe.user_data = reinterpret_cast<std::uintptr_t>(
                        static_cast<base_operation *>(this));
                this->execute_ = &base_operation::on_operation_complete;
            };

            if (!context_.try_submit_io(populateSqe)) {
                this->execute_ = &base_operation::on_schedule_complete;
                context_.schedule_pending_io(this);
            }
#elif G6_IO_USE_EPOLL_CONTEXT
            const auto[data, len, off] = get_impl_io_data();
            int result = -1;
            if constexpr (op_code == detail::io_operation_id::readv) {
                iovec iovec{.iov_base = data, .iov_len = len};
                result = ::readv(fd_, &iovec, 1);
            } else if constexpr (op_code == detail::io_operation_id::writev) {
                iovec iovec{.iov_base = data, .iov_len = len};
                result = ::writev(fd_, &iovec, 1);
            }else if constexpr (op_code == detail::io_operation_id::send) {
                iovec iovec{.iov_base = data, .iov_len = len};
                result = ::send(fd_, data, len, 0);
            }

            if (result == -EAGAIN || result == -EWOULDBLOCK || result == -EPERM) {
                if constexpr (is_stop_ever_possible) {
                    stopCallback_.construct(
                            get_stop_token(receiver_), cancel_callback{*this});
                }
                assert(static_cast<completion_base*>(this)->enqueued_.load() == 0);
                static_cast<completion_base*>(this)->execute_ = &operation::on_read_complete;
                epoll_event event;
                event.data.ptr = static_cast<completion_base*>(this);
                event.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
                (void)epoll_ctl(context_.epollFd_.get(), EPOLL_CTL_ADD, fd_, &event);
                return;
            }

            auto oldState = state_.fetch_add(
                    io_epoll_context::read_sender::operation<Receiver>::io_flag,
                    std::memory_order_acq_rel);
            if ((oldState & io_epoll_context::read_sender::operation<Receiver>::cancel_pending_mask) != 0) {
                // io has been cancelled by a remote thread.
                // The other thread is responsible for enqueueing the operation completion
                return;
            }

            if (result == -ECANCELED) {
                unifex::set_done(std::move(receiver_));
            } else if (result >= 0) {
                if constexpr (is_nothrow_receiver_of_v<Receiver, ssize_t>) {
                    unifex::set_value(std::move(receiver_), ssize_t(result));
                } else {
                    UNIFEX_TRY {
                        unifex::set_value(std::move(receiver_), ssize_t(result));
                    } UNIFEX_CATCH (...) {
                        unifex::set_error(std::move(receiver_), std::current_exception());
                    }
                }
            } else {
                unifex::set_error(
                        std::move(receiver_),
                        std::error_code{-int(result), std::system_category()});
            }
#elif G6_IO_USE_IOCP_CONTEXT
#endif
        }

        void set_result(int result) noexcept {
            result_ = result;
        }

        auto get_impl_result() noexcept {
            if constexpr (requires {
                { get_impl(this).get_result() };
            }) {
                return get_impl(this).get_result();
            } else {
                return size_t(result_);
            }
        }

        static void on_operation_complete(operation_base *op) noexcept {
            auto &self = get_impl(op);
            if (self.result_ >= 0) {
                if constexpr (noexcept(unifex::set_value(std::move(self.receiver_), self.get_impl_result()))) {
                    unifex::set_value(std::move(self.receiver_), self.get_impl_result());
                } else {
                    UNIFEX_TRY {
                        unifex::set_value(std::move(self.receiver_), self.get_impl_result());
                    }
                    UNIFEX_CATCH(...) {
                        unifex::set_error(std::move(self.receiver_), std::current_exception());
                    }
                }
            } else if (self.result_ == -ECANCELED) {
                unifex::set_done(std::move(self.receiver_));
            } else {
                unifex::set_error(
                        std::move(self.receiver_),
                        std::error_code{-self.result_, std::system_category()});
            }
        }

    protected:
        io::context &context_;
        int fd_;
        Receiver receiver_;
    };

    class context::base_sender {
        using offset_t = std::int64_t;

        template<detail::io_operation_id, typename, typename>
        friend class base_operation;

    public:
        // Produces number of bytes read.
        template<
                template<typename...> class Variant,
                template<typename...> class Tuple>
        using value_types = Variant<Tuple<size_t>>;

        // Note: Only case it might complete with exception_ptr is if the
        // receiver's set_value() exits with an exception.
        template<template<typename...> class Variant>
        using error_types = Variant<std::error_code, std::exception_ptr>;

        static constexpr bool sends_done = true;

        explicit base_sender(
                context &context,
                int fd) noexcept
                : context_(context), fd_(fd) {}
        base_sender(base_sender &&) = default;
        base_sender(base_sender const&) = delete;

    private:
        context &context_;
        int fd_;
    };

}// namespace g6::io
