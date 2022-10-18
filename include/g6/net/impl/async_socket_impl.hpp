#pragma once


#include <g6/coro/io_context.hpp>
#include <g6/io/config.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>

#include <cstddef>
#include <functional>
#include <stop_token>

#if G6_OS_WINDOWS
#include <MSWSock.h>
#else
#include <g6/coro/linux/uring_queue.hpp>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace g6::net {
    namespace detail {

        template<typename Operation>
        class net_operation_base : public io_context::operation_base<Operation> {
            using base = io_context::operation_base<Operation>;

        public:
            template<typename Promise>
            auto await_suspend(std::coroutine_handle<Promise> awaiter) {
#if G6_OS_WINDOWS
                const bool skipCompletionOnSuccess = socket_.skip_completion_;
                auto result = base::await_suspend(awaiter);
                if (result == SOCKET_ERROR) {
                    int errorCode = ::WSAGetLastError();
                    if (errorCode != WSA_IO_PENDING) {
                        // Failed synchronously.
                        error_code_ = errorCode;
                        return false;
                    }
                } else if (skipCompletionOnSuccess) {
                    // Completed synchronously, no completion event will be posted to the IOCP.
                    error_code_ = ERROR_SUCCESS;
                    return false;
                }

                // Operation will complete asynchronously.
                return true;
#else
                return base::await_suspend(awaiter);
#endif
            }

            explicit net_operation_base(io::context &context, async_socket &socket) noexcept
                : base{context, socket.get_fd()}, context_{context}, socket_{socket} {}
            net_operation_base(net_operation_base &&other) noexcept
                : base{std::move(other)}, context_{other.context_}, socket_{other.socket_} {}

        protected:
            io::context &context_;
            async_socket &socket_;
        };

#if G6_IO_USE_IO_URING_CONTEXT
        class send_to_sender : public net_operation_base<send_to_sender> {
        public:
            bool start_operation() noexcept {
                return context_.io_queue().transaction(*this).sendmsg(socket_.get_fd(), msghdr_).commit();
            }

            auto finalize_operation() noexcept { return this->byte_count_; }

            explicit send_to_sender(io::context &context, async_socket &socket, const net::ip_endpoint &endpoint,
                                    std::span<const std::byte> buffer) noexcept
                : net_operation_base<send_to_sender>{context, socket}, iovec_{const_cast<std::byte *>(buffer.data()),
                                                                              buffer.size_bytes()} {
                endpoint.to_sockaddr(sockaddr_storage_);
            }

        private:
            sockaddr_storage sockaddr_storage_;
            iovec iovec_;
            msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1, nullptr, 0, 0};
        };

        class send_sender : public net_operation_base<send_sender> {
        public:
            bool start_operation() noexcept {
                return context_.io_queue()
                    .transaction(*this)
                    .send(socket_.get_fd(), buffer_.data(), buffer_.size_bytes())
                    .commit();
            }

            auto finalize_operation() noexcept { return this->byte_count_; }

            explicit send_sender(io::context &context, async_socket &socket, std::span<const std::byte> buffer) noexcept
                : net_operation_base<send_sender>{context, socket}, buffer_{buffer} {}

        private:
            std::span<const std::byte> buffer_;
        };

        class recv_from_sender : public net_operation_base<recv_from_sender> {
        public:
            bool start_operation() noexcept {
                return context_.io_queue().transaction(*this).recvmsg(socket_.get_fd(), msghdr_).commit();
            }

            auto finalize_operation() noexcept {
                return std::make_tuple(
                    this->byte_count_,
                    ip_endpoint::from_sockaddr(sockaddr_storage_));
            }

            explicit recv_from_sender(io::context &context, async_socket &socket, std::span<std::byte> buffer) noexcept
                : net_operation_base<recv_from_sender>{context, socket}, iovec_{buffer.data(), buffer.size_bytes()} {}

            recv_from_sender(recv_from_sender &&other) noexcept
                : net_operation_base<recv_from_sender>{std::move(other)}, iovec_{other.iovec_} {
                std::memcpy(&sockaddr_storage_, &other.sockaddr_storage_, sizeof(sockaddr_storage_));
            }

        private:
            sockaddr_storage sockaddr_storage_;
            iovec iovec_;
            msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1, nullptr, 0, 0};
        };

        class recv_sender : public net_operation_base<recv_sender> {
        public:
            bool start_operation() noexcept {
                return context_.io_queue()
                    .transaction(*this)
                    .recv(socket_.get_fd(), buffer_.data(), buffer_.size_bytes())
                    .commit();
            }

            auto finalize_operation() noexcept { return this->byte_count_; }

            explicit recv_sender(io::context &context, async_socket &socket, std::span<std::byte> buffer) noexcept
                : net_operation_base<recv_sender>{context, socket}, buffer_{buffer} {}

        private:
            std::span<std::byte> buffer_;
        };

        class accept_sender : public net_operation_base<accept_sender> {
        public:
            bool start_operation() noexcept {
                return context_.io_queue()
                    .transaction(*this)
                    .accept(socket_.get_fd(), &sockaddr_storage_, &sockaddr_storage_len_, 0)
                    .commit();
            }

            auto finalize_operation() noexcept {
                return std::make_tuple(
                    async_socket{context_, int(this->byte_count_), socket_.protocol()},
                    ip_endpoint::from_sockaddr(sockaddr_storage_));
            }

            explicit accept_sender(io::context &context, async_socket &socket) noexcept
                : net_operation_base<accept_sender>{context, socket} {}

        private:
            sockaddr_storage sockaddr_storage_;
            socklen_t sockaddr_storage_len_ = sizeof(sockaddr_storage_);
        };

        class connect_sender : public net_operation_base<connect_sender> {
        public:
            bool start_operation() noexcept {
                return context_.io_queue()
                    .transaction(*this)
                    .connect(socket_.get_fd(), &sockaddr_storage_, sockaddr_storage_len_)
                    .commit();
            }

            auto finalize_operation() noexcept {
                return std::make_tuple(
                    this->byte_count_,
                    ip_endpoint::from_sockaddr(sockaddr_storage_));
            }

            explicit connect_sender(io::context &context, async_socket &socket, ip_endpoint const &to) noexcept
                : net_operation_base<connect_sender>{context, socket} {
                auto sz = to.to_sockaddr(sockaddr_storage_);
                assert(sz >= 0);
                sockaddr_storage_len_ = size_t(sz);
            }

        private:
            sockaddr_storage sockaddr_storage_;
            size_t sockaddr_storage_len_;
        };

#elif G6_IO_USE_EPOLL_CONTEXT
#error "not implemented"
#else// G6_IO_USE_IOCP_CONTEXT

        template<typename Operation>
        class wsa_operation_base : protected operation_base {
        public:
            bool await_ready() const noexcept { return false; }
            auto await_suspend(std::coroutine_handle<> awaiter) {
                awaiter_ = awaiter;

                const bool skipCompletionOnSuccess = socket_.skip_completion_;
                auto result = static_cast<Operation &>(*this).start_op();
                if (result == SOCKET_ERROR) {
                    int errorCode = ::WSAGetLastError();
                    if (errorCode != WSA_IO_PENDING) {
                        // Failed synchronously.
                        error_code_ = errorCode;
                        return false;
                    }
                } else if (skipCompletionOnSuccess) {
                    // Completed synchronously, no completion event will be posted to the IOCP.
                    error_code_ = ERROR_SUCCESS;
                    return false;
                }

                // Operation will complete asynchronously.
                return true;
            }
            auto await_resume() {
                if (error_code_ != 0) {
#if G6_OS_WINDOWS
                    if (error_code_ == WSA_OPERATION_ABORTED) {
                        throw std::system_error{std::make_error_code(std::errc::operation_canceled)};
                    }
#endif
                    throw std::system_error{error_code_, std::system_category()};
                }
                return static_cast<Operation &>(*this).op_result();
            }

            explicit wsa_operation_base(io::context &context, async_socket &socket, std::span<const std::byte> buffer,
                                        std::stop_token stop_token) noexcept
                : context_{context}, socket_{socket},
                  on_stop_requested_{stop_token, [this]() noexcept {
                                         (void) ::CancelIoEx(reinterpret_cast<HANDLE>(socket_.fd_.get()),
                                                             reinterpret_cast<_OVERLAPPED *>(this));
                                         static_cast<Operation &>(*this).op_cancelled();
                                     }} {
                buffer_.len = ULONG(buffer.size());
                buffer_.buf = reinterpret_cast<decltype(buffer_.buf)>(const_cast<std::byte *>(buffer.data()));
            }

        protected:
            io::context &context_;
            async_socket &socket_;
            WSABUF buffer_;
            std::stop_callback<std::function<void()>> on_stop_requested_;
        };

        class send_to_sender : public wsa_operation_base<send_to_sender> {
            friend class wsa_operation_base<send_to_sender>;
            auto start_op() {
                SOCKADDR_STORAGE destinationAddress;
                const int destinationLength = to_.to_sockaddr(destinationAddress);

                DWORD numberOfBytesSent = 0;
                auto result = ::WSASendTo(socket_.fd_.get(), reinterpret_cast<WSABUF *>(&buffer_),
                                          1,// buffer count
                                          &numberOfBytesSent,
                                          0,// flags
                                          reinterpret_cast<const SOCKADDR *>(&destinationAddress), destinationLength,
                                          reinterpret_cast<_OVERLAPPED *>(this), nullptr);
                byte_count_ = numberOfBytesSent;
                return result;
            }

            void op_cancelled() const noexcept {}

            auto op_result() const noexcept { return byte_count_; }

        public:
            explicit send_to_sender(io::context &context, async_socket &socket, const net::ip_endpoint &endpoint,
                                    std::span<const std::byte> buffer, std::stop_token stop_token) noexcept
                : wsa_operation_base<send_to_sender>{context, socket, buffer, stop_token}, to_{endpoint} {}

        private:
            net::ip_endpoint to_;
        };

        class send_sender : public wsa_operation_base<send_sender> {
            friend class wsa_operation_base<send_sender>;
            auto start_op() {
                DWORD numberOfBytesSent = 0;
                auto result = ::WSASend(socket_.fd_.get(), reinterpret_cast<WSABUF *>(&buffer_),
                                        1,// buffer count
                                        &numberOfBytesSent,
                                        0,// flags
                                        reinterpret_cast<_OVERLAPPED *>(this), nullptr);
                byte_count_ = numberOfBytesSent;
                return result;
            }

            void op_cancelled() const noexcept {}

            auto op_result() const noexcept { return byte_count_; }

        public:
            explicit send_sender(io::context &context, async_socket &socket, std::span<const std::byte> buffer,
                                 std::stop_token stop_token) noexcept
                : wsa_operation_base<send_sender>{context, socket, buffer, stop_token} {}
        };

        class recv_from_sender : public wsa_operation_base<recv_from_sender> {
            friend class wsa_operation_base<recv_from_sender>;
            auto start_op() {
                DWORD numberOfBytesRecvd = 0;
                DWORD flags = 0;
                auto result = ::WSARecvFrom(socket_.fd_.get(), reinterpret_cast<WSABUF *>(&buffer_),
                                            1,// buffer count
                                            &numberOfBytesRecvd,
                                            &flags,// flags
                                            reinterpret_cast<SOCKADDR *>(&from_), &from_len_,
                                            reinterpret_cast<_OVERLAPPED *>(this), nullptr);
                byte_count_ = numberOfBytesRecvd;
                return result;
            }

            void op_cancelled() const noexcept {}

            auto op_result() noexcept {
                return std::make_tuple(byte_count_,
                                       net::ip_endpoint::from_sockaddr(*reinterpret_cast<sockaddr *>(&from_)));
            }

        public:
            explicit recv_from_sender(io::context &context, async_socket &socket, std::span<const std::byte> buffer,
                                      std::stop_token stop_token) noexcept
                : wsa_operation_base<recv_from_sender>{context, socket, buffer, stop_token} {}

        private:
            SOCKADDR_STORAGE from_{0};
            int from_len_{sizeof(SOCKADDR_STORAGE)};
        };

        class recv_sender : public wsa_operation_base<recv_sender> {
            friend class wsa_operation_base<recv_sender>;
            auto start_op() {
                DWORD numberOfBytesRecvd = 0;
                DWORD flags = 0;
                auto result = ::WSARecv(socket_.fd_.get(), reinterpret_cast<WSABUF *>(&buffer_),
                                        1,// buffer count
                                        &numberOfBytesRecvd,
                                        &flags,// flags
                                        reinterpret_cast<_OVERLAPPED *>(this), nullptr);
                byte_count_ = numberOfBytesRecvd;
                return result;
            }

            void op_cancelled() const noexcept {}

            auto op_result() const noexcept { return byte_count_; }

        public:
            explicit recv_sender(io::context &context, async_socket &socket, std::span<const std::byte> buffer,
                                 std::stop_token stop_token) noexcept
                : wsa_operation_base<recv_sender>{context, socket, buffer, stop_token} {}
        };

        class accept_sender : public wsa_operation_base<accept_sender> {
            friend class wsa_operation_base<accept_sender>;
            auto start_op() {
                DWORD numberOfBytesRecvd = 0;
                DWORD flags = 0;
                auto ok = ::AcceptEx(socket_.fd_.get(), accepting_socket_->fd_.get(), address_buffer_, 0,
                                     sizeof(address_buffer_) / 2, sizeof(address_buffer_) / 2, &numberOfBytesRecvd,
                                     reinterpret_cast<_OVERLAPPED *>(this));
                byte_count_ = numberOfBytesRecvd;
                return ok ? 0 : SOCKET_ERROR;
            }

            void op_cancelled() const noexcept {}

            auto op_result() {
                sockaddr *localSockaddr = nullptr;
                sockaddr *remoteSockaddr = nullptr;
                INT localSockaddrLength;
                INT remoteSockaddrLength;

                ::GetAcceptExSockaddrs(address_buffer_, 0, sizeof(address_buffer_) / 2, sizeof(address_buffer_) / 2,
                                       &localSockaddr, &localSockaddrLength, &remoteSockaddr, &remoteSockaddrLength);

                {
                    using update_context_opt =
                        net::simple_socket_option<SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, SOCKET, SOCKET>;
                    // Need to set SO_UPDATE_ACCEPT_CONTEXT after the accept completes
                    // to ensure that ::shutdown() and ::setsockopt() calls work on the
                    // accepted socket.
                    accepting_socket_->setopt<update_context_opt>(accepting_socket_->get_fd());
                }

                return std::make_tuple(std::move(accepting_socket_).value(),
                                       net::ip_endpoint::from_sockaddr(*remoteSockaddr));
            }

        public:
            explicit accept_sender(io::context &context, async_socket &socket, std::stop_token stop_token) noexcept
                : wsa_operation_base<accept_sender>{context, socket, std::span<std::byte, 0>{}, stop_token} {
                auto [handle, iocp_skip] = io::create_socket(socket.protocol(), context.iocp_handle());
                accepting_socket_.emplace(context, handle, socket.protocol(), iocp_skip);
            }

        private:
            alignas(8) std::uint8_t address_buffer_[88];
            int from_len_{sizeof(SOCKADDR_STORAGE)};
            std::optional<async_socket> accepting_socket_;
        };

        class connect_sender : public wsa_operation_base<connect_sender> {
            friend class wsa_operation_base<connect_sender>;
            auto start_op() {
                LPFN_CONNECTEX connectExPtr;
                {
                    GUID connectExGuid = WSAID_CONNECTEX;
                    DWORD byteCount = 0;
                    int result = ::WSAIoctl(socket_.fd_.get(), SIO_GET_EXTENSION_FUNCTION_POINTER,
                                            static_cast<void *>(&connectExGuid), sizeof(connectExGuid),
                                            static_cast<void *>(&connectExPtr), sizeof(connectExPtr), &byteCount,
                                            nullptr, nullptr);
                    if (result == SOCKET_ERROR) { return SOCKET_ERROR; }
                }
                SOCKADDR_STORAGE remoteSockaddrStorage;
                const int sockaddrNameLength = to_.to_sockaddr(remoteSockaddrStorage);
                DWORD bytesSent = 0;
                const BOOL ok = connectExPtr(
                    socket_.fd_.get(), reinterpret_cast<const SOCKADDR *>(&remoteSockaddrStorage), sockaddrNameLength,
                    nullptr,// send buffer
                    0,      // size of send buffer
                    &bytesSent, reinterpret_cast<_OVERLAPPED *>(this));
                return ok ? 0 : SOCKET_ERROR;
            }

            void op_cancelled() const noexcept {}

            auto op_result() noexcept {
                // We need to call setsockopt() to update the socket state with information
                // about the connection now that it has been successfully connected.
                {
                    using update_connect_context = net::empty_socket_option<SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT>;
                    socket_.setopt<update_connect_context>();
                }
            }

        public:
            explicit connect_sender(io::context &context, async_socket &socket, ip_endpoint const &to,
                                    std::stop_token stop_token) noexcept
                : wsa_operation_base<connect_sender>{context, socket, std::span<std::byte, 0>{}, stop_token}, to_{to} {}

        private:
            ip_endpoint to_;
        };
#endif
    }// namespace detail

    inline auto tag_invoke(tag_t<async_accept>, async_socket &socket) noexcept {
        return detail::accept_sender{socket.context_, socket};
    }

    inline auto tag_invoke(tag_t<async_connect>, async_socket &socket, ip_endpoint const &endpoint) noexcept {
        return [](async_socket &socket, ip_endpoint const &endpoint) -> task<void> {
            co_await detail::connect_sender{socket.context_, socket, endpoint};
        }(socket, endpoint);
    }

    inline auto tag_invoke(tag_t<async_send>, async_socket &socket, std::span<const std::byte> buffer) noexcept {
        return [](async_socket &socket, std::span<const std::byte> buffer) -> task<size_t> {
            co_return co_await detail::send_sender{socket.context_, socket, buffer};
        }(socket, buffer);
    }

    inline auto tag_invoke(tag_t<async_recv>, async_socket &socket, std::span<std::byte> buffer) noexcept {
        return [](async_socket &socket, std::span<std::byte> buffer) -> task<size_t> {
            co_return co_await detail::recv_sender{socket.context_, socket, buffer};
        }(socket, buffer);
    }

    inline auto tag_invoke(tag_t<async_send_to>, async_socket &socket, std::span<const std::byte> buffer,
                           net::ip_endpoint const &endpoint) noexcept {
        return detail::send_to_sender{socket.context_, socket, endpoint, buffer};
    }

    inline auto tag_invoke(tag_t<async_recv_from>, async_socket &socket, std::span<std::byte> buffer) noexcept {
        return detail::recv_from_sender{socket.context_, socket, buffer};
    }

    inline auto tag_invoke(tag_t<pending_bytes>, async_socket &socket) noexcept {
#if G6_OS_WINDOWS
        unsigned long count = 0;
        DWORD out_sz = 0;
        (void) ::WSAIoctl(socket.fd_.get(), FIONREAD, nullptr, 0, &count, sizeof(count), &out_sz, nullptr, nullptr);
#else
        int count = 0;
        (void) ::ioctl(socket.fd_.get(), FIONREAD, &count);
#endif
        return size_t(count);
    }
    inline auto tag_invoke(tag_t<has_pending_data>, async_socket &socket) noexcept { return pending_bytes(socket) > 0; }

    // template<class IOContext2>
    // auto tag_invoke(tag_t<net::open_socket>, IOContext2 &ctx, net::detail::tags::tcp const &,
    //                 const net::ip_endpoint &endpoint) {
    //     auto sock = net::open_socket(ctx, AF_INET, SOCK_STREAM);
    //     sock.bind(endpoint);
    //     sock.listen();
    //     return sock;
    // }

    // template<class IOContext2>
    // auto tag_invoke(tag_t<net::open_socket>, IOContext2 &ctx, net::detail::tags::tcp const &) {
    //     return net::open_socket(ctx, AF_INET, SOCK_STREAM);
    // }

}// namespace g6::net

namespace g6::io {
    inline auto tag_invoke(tag_t<net::open_socket>, io::context &ctx, net::socket_protocol sock_type) {
#if G6_OS_WINDOWS
        auto [socket, skip_completion] = create_socket(sock_type, ctx.iocp_handle());
        if (socket == INVALID_SOCKET) {
            int errorCode = ::WSAGetLastError();
            throw std::system_error{errorCode, std::system_category()};
        }
        return net::async_socket{ctx, socket, sock_type, skip_completion};
#else
        auto socket = ::socket(sock_type.domain, sock_type.type, sock_type.proto);
        if (socket < 0) { throw std::system_error{-errno, std::system_category()}; }
        return net::async_socket{ctx, socket, sock_type};
#endif
    }
}// namespace g6::io