#pragma once

#include <g6/net/async_socket.hpp>

#include <g6/io/config.hpp>

#if G6_OS_WINDOWS
#include <MSWSock.h>
#else
#include <sys/ioctl.h>
#endif

namespace g6::net {
    namespace detail {

#if G6_IO_USE_IO_URING_CONTEXT
        class accept_sender {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_ACCEPT, Receiver, operation> {
                friend io::context;

                explicit operation(accept_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_ACCEPT, Receiver, operation>{sender, (Receiver &&) r} {}
                auto get_io_data() noexcept {
                    return std::tuple{reinterpret_cast<std::byte *>(&sockaddr_storage_), 0,
                                      reinterpret_cast<uint64_t>(&socklen_)};
                }
                auto get_result() noexcept {
                    return std::make_tuple(
                        async_socket{this->context_, this->result_},
                        net::ip_endpoint::from_sockaddr(*reinterpret_cast<const sockaddr *>(&sockaddr_storage_)));
                }
                socklen_t socklen_{sizeof(sockaddr_storage)};
                sockaddr_storage sockaddr_storage_{};
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<std::tuple<async_socket, net::ip_endpoint>>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit accept_sender(io::context &context, int fd) noexcept : context_{context}, fd_{fd} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
        };

        class connect_sender {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_CONNECT, Receiver, operation> {

                friend io::context;

                explicit operation(connect_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_CONNECT, Receiver, operation>{sender, (Receiver &&) r} {
                    addr_len_ = sender.endpoint_.to_sockaddr(sockaddr_storage_);
                }

                auto get_result() noexcept { return int(this->result_); }

                auto get_io_data() noexcept {
                    return std::tuple{reinterpret_cast<std::byte *>(&sockaddr_storage_), 0, addr_len_};
                }
                sockaddr_storage sockaddr_storage_{};
                size_t addr_len_;
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<int>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit connect_sender(io::context &context, int fd, const net::ip_endpoint &endpoint) noexcept
                : context_{context}, fd_{fd}, endpoint_{endpoint} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            net::ip_endpoint endpoint_;
        };

        class recv_sender {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_RECV, Receiver, operation> {
                friend io::context;

                explicit operation(recv_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_RECV, Receiver, operation>{sender, (Receiver &&) r},
                      buffer_{sender.buffer_} {}
                auto get_io_data() noexcept { return std::tuple{buffer_.data(), buffer_.size(), 0}; }
                auto get_result() noexcept { return size_t(this->result_); }
                span<std::byte> buffer_;
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit recv_sender(io::context &context, int fd, span<std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<std::byte> buffer_;
        };

        class recv_from_sender {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_RECVMSG, Receiver, operation> {
                friend io::context;

                explicit operation(recv_from_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_RECVMSG, Receiver, operation>{sender, (Receiver &&) r} {
                    iovec_.iov_base = const_cast<std::byte *>(sender.buffer_.data());
                    iovec_.iov_len = sender.buffer_.size();
                }
                auto get_io_data() noexcept { return std::tuple{&msghdr_, 1, 0}; }
                auto get_result() noexcept {
                    return std::make_tuple(
                        size_t(this->result_),
                        net::ip_endpoint::from_sockaddr(*reinterpret_cast<sockaddr *>(&sockaddr_storage_)));
                }
                sockaddr_storage sockaddr_storage_;
                iovec iovec_;
                msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1};
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t, net::ip_endpoint>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit recv_from_sender(io::context &context, int fd, span<std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<const std::byte> buffer_;
        };

        class send_sender {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_SEND, Receiver, operation> {
                friend io::context;

                explicit operation(send_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_SEND, Receiver, operation>{sender, (Receiver &&) r},
                      buffer_{sender.buffer_} {}
                auto get_io_data() noexcept { return std::tuple{buffer_.data(), buffer_.size(), 0}; }
                auto get_result() noexcept { return size_t(this->result_); }
                span<const std::byte> buffer_;
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit send_sender(io::context &context, int fd, span<const std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<const std::byte> buffer_;
        };

        class send_to_sender {
            template<typename Receiver>
            struct operation : io::context::io_operation_base<IORING_OP_SENDMSG, Receiver, operation> {
                friend io::context;

                explicit operation(send_to_sender &sender, Receiver &&r)
                    : io::context::io_operation_base<IORING_OP_SENDMSG, Receiver, operation>{sender, (Receiver &&) r} {
                    iovec_.iov_base = const_cast<std::byte *>(sender.buffer_.data());
                    iovec_.iov_len = sender.buffer_.size();
                    msghdr_.msg_namelen = sender.to_.to_sockaddr(sockaddr_storage_);
                }
                auto get_io_data() noexcept { return std::tuple{&msghdr_, 1, 0}; }
                auto get_result() noexcept { return size_t(this->result_); }
                sockaddr_storage sockaddr_storage_;
                iovec iovec_;
                msghdr msghdr_{&sockaddr_storage_, sizeof(sockaddr_storage_), &iovec_, 1};
            };
            template<auto, typename, template<class> typename>
            friend class io::context::io_operation_base;

        public:
            // Produces number of bytes read.
            template<template<typename...> class Variant, template<typename...> class Tuple>
            using value_types = Variant<Tuple<size_t>>;

            // Note: Only case it might complete with exception_ptr is if the
            // receiver's set_value() exits with an exception.
            template<template<typename...> class Variant>
            using error_types = Variant<std::error_code, std::exception_ptr>;

            static constexpr bool sends_done = true;

            explicit send_to_sender(io::context &context, int fd, const net::ip_endpoint &endpoint,
                                    span<const std::byte> buffer) noexcept
                : context_{context}, fd_{fd}, buffer_{buffer}, to_{endpoint} {}

            template<typename Receiver>
            auto connect(Receiver &&r) && {
                return operation<Receiver>{*this, (Receiver &&) r};
            }

        private:
            io::context &context_;
            int fd_;
            span<const std::byte> buffer_;
            net::ip_endpoint to_;
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
                if (error_code_ != 0) { throw std::system_error{error_code_, std::system_category()}; }
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
                buffer_.len = buffer.size();
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
                    // Need to set SO_UPDATE_ACCEPT_CONTEXT after the accept completes
                    // to ensure that ::shutdown() and ::setsockopt() calls work on the
                    // accepted socket.
                    SOCKET listenSocket = accepting_socket_->fd_.get();
                    const int result = ::setsockopt(listenSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                                                    (const char *) &listenSocket, sizeof(SOCKET));
                    if (result == SOCKET_ERROR) {
                        const int errorCode = ::WSAGetLastError();
                        throw std::system_error{errorCode, std::system_category(),
                                                "Socket accept operation failed: setsockopt(SO_UPDATE_ACCEPT_CONTEXT)"};
                    }
                }

                return std::make_tuple(std::move(accepting_socket_).value(),
                                       net::ip_endpoint::from_sockaddr(*remoteSockaddr));
            }

        public:
            explicit accept_sender(io::context &context, async_socket &socket, std::stop_token stop_token) noexcept
                : wsa_operation_base<accept_sender>{context, socket, std::span<std::byte, 0>{}, stop_token} {
                auto [handle, iocp_skip] =
                    io::create_socket(socket.domain(), socket.type(), socket.proto(), context.iocp_handle());
                accepting_socket_.emplace(context, handle, socket.domain(), socket.type(), socket.proto(), iocp_skip);
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
                    const int result =
                        ::setsockopt(socket_.fd_.get(), SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0);
                    if (result == SOCKET_ERROR) {
                        // This shouldn't fail, but just in case it does we fall back to
                        // setting the remote address as specified in the call to Connect().
                        //
                        // Don't really want to throw an exception here since the connection
                        // has actually been established.
                        return;
                    }
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

    auto tag_invoke(tag<async_accept>, async_socket &socket, std::stop_token stop_token = {}) noexcept {
        return detail::accept_sender{socket.context_, socket, stop_token};
    }

    auto tag_invoke(tag<async_connect>, async_socket &socket, ip_endpoint const &endpoint,
                    std::stop_token stop_token = {}) noexcept {
        return detail::connect_sender{socket.context_, socket, endpoint, stop_token};
    }

    // auto tag_invoke(tag<async_connect>, async_socket &socket, ip_endpoint &&endpoint) noexcept {
    //     return detail::connect_sender{socket.context_, socket.fd_.get(), std::forward<ip_endpoint>(endpoint)};
    // }

    // auto tag_invoke(tag<async_connect>, auto &context, int fd, ip_endpoint const &endpoint) noexcept {
    //     return detail::connect_sender{context, fd, endpoint};
    // }

    auto tag_invoke(tag<async_send>, async_socket &socket, std::span<const std::byte> buffer,
                    std::stop_token stop_token = {}) noexcept {
        return detail::send_sender{socket.context_, socket, buffer, stop_token};
    }

    auto tag_invoke(tag<async_recv>, async_socket &socket, std::span<std::byte> buffer,
                    std::stop_token stop_token = {}) noexcept {
        return detail::recv_sender{socket.context_, socket, buffer, stop_token};
    }

    auto tag_invoke(tag<async_send_to>, async_socket &socket, std::span<const std::byte> buffer,
                    net::ip_endpoint const &endpoint, std::stop_token stop_token = {}) noexcept {
        return detail::send_to_sender{socket.context_, socket, endpoint, buffer, stop_token};
    }

    auto tag_invoke(tag<async_recv_from>, async_socket &socket, std::span<std::byte> buffer,
                    std::stop_token stop_token = {}) noexcept {
        return detail::recv_from_sender{socket.context_, socket, buffer, stop_token};
    }

    auto tag_invoke(tag<pending_bytes>, async_socket &socket) noexcept {
#if G6_OS_WINDOWS
        unsigned long count = 0;
        DWORD out_sz = 0;
        (void) ::WSAIoctl(socket.fd_.get(), FIONREAD, nullptr, 0, &count, sizeof(count), &out_sz, nullptr, nullptr);
#else
        int count = 0;
        (void) ::ioctl(socket.fd_.get(), FIONREAD, &count);
#endif
        return count;
    }
    auto tag_invoke(tag<has_pending_data>, async_socket &socket) noexcept { return pending_bytes(socket) > 0; }

    // template<class IOContext2>
    // auto tag_invoke(tag<net::open_socket>, IOContext2 &ctx, net::detail::tags::tcp_server const &,
    //                 const net::ip_endpoint &endpoint) {
    //     auto sock = net::open_socket(ctx, AF_INET, SOCK_STREAM);
    //     sock.bind(endpoint);
    //     sock.listen();
    //     return sock;
    // }

    // template<class IOContext2>
    // auto tag_invoke(tag<net::open_socket>, IOContext2 &ctx, net::detail::tags::tcp_client const &) {
    //     return net::open_socket(ctx, AF_INET, SOCK_STREAM);
    // }
}// namespace g6::net
