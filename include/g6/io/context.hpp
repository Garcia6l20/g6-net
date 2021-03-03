#pragma once

#if __has_include(<liburing.h>)
#include <unifex/linux/io_uring_context.hpp>
#include <liburing.h>
#define G6_OS_LINUX  true
#define G6_IO_USE_IO_URING  true
#else
#error "Cannot find suitable IO context"
#endif

namespace g6 {
    using namespace unifex;
#if G6_OS_LINUX
    using namespace unifex::linuxos;
#endif
}

namespace g6::io {
    class context : public io_uring_context
    {
    public:
        using io_uring_context::io_uring_context;
        class scheduler : public io_uring_context::scheduler
        {
        public:
            explicit scheduler(context &ctx, io_uring_context::scheduler sched) : context_{ctx}, io_uring_context::scheduler{sched} {}
            [[nodiscard]] auto &get_context() const { return context_; }

        private:
            context &context_;
        };
        inline auto get_scheduler() noexcept {
            return scheduler{*this, io_uring_context::get_scheduler()};
        }

    public:
        template<uint8_t op_code, typename Receiver, typename CRTP = void>
        class base_operation;
        class base_sender;
    };

    template<uint8_t op_code, typename Receiver, typename CRTP>
    class context::base_operation : protected completion_base
    {
        friend io_uring_context;

    public:
        template<typename Receiver2>
        explicit base_operation(const auto &sender, Receiver2 &&r)
            : context_(sender.context_),
              fd_(sender.fd_),
              offset_{sender.offset_},
              io_data_{sender.io_data_},
              receiver_((Receiver2 &&) r) {
            result_ = -1;
        }

        void start() noexcept {
            if (!context_.is_running_on_io_thread()) {
                this->execute_ = &base_operation::on_schedule_complete;
                context_.schedule_remote(this);
            } else {
                start_io();
            }
        }

    private:
        static auto &get_impl(operation_base *op) {
            if constexpr (not std::is_void_v<CRTP>) {
                return *static_cast<CRTP *>(op);
            } else {
                return *static_cast<base_operation *>(op);
            }
        }

        static void on_schedule_complete(operation_base *op) noexcept {
            static_cast<base_operation *>(op)->start_io();
        }

        void start_io() noexcept {
            assert(context_.is_running_on_io_thread());

            auto populateSqe = [this](io_uring_sqe &sqe) noexcept {
              io_uring_prep_rw(op_code, &sqe, fd_, io_data_, 1, offset_);
              sqe.user_data = reinterpret_cast<std::uintptr_t>(
                  static_cast<base_operation *>(this));
              this->execute_ = &base_operation::on_operation_complete;
            };

            if (!context_.try_submit_io(populateSqe)) {
                this->execute_ = &base_operation::on_schedule_complete;
                context_.schedule_pending_io(this);
            }
        }

        auto get_impl_result() noexcept {
            if constexpr (requires {
                {get_impl(this).get_result()};
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

        context &context_;
        int fd_;
        int64_t offset_;
        const void *io_data_;
        Receiver receiver_;
    };

    class context::base_sender
    {
        using offset_t = std::int64_t;

        template<uint8_t, typename, typename>
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

    private:
        context &context_;
        int fd_;
    };

}// namespace g6::io
