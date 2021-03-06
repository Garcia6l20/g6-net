/** @file g6/net/ssl/socket.hpp
 * @author Sylvain Garcia <garcia.6l20@gmail.com>
 */
#pragma once

#include <g6/ssl/certificate.hpp>
#include <g6/ssl/context.hpp>
#include <g6/ssl/key.hpp>
#include <g6/ssl/ssl_cpo.hpp>

#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>

#include <unifex/task.hpp>

#include <utility>

#include <spdlog/spdlog.h>

//#define G6_SSL_DEBUG

namespace g6::ssl {

    namespace detail::tags {
        struct tcp_server {};
        struct tcp_client {};
    }// namespace detail::tags

    inline const ssl::detail::tags::tcp_server tcp_server;
    inline const ssl::detail::tags::tcp_client tcp_client;

    enum class peer_verify_mode
    {
        none = MBEDTLS_SSL_VERIFY_NONE,
        required = MBEDTLS_SSL_VERIFY_REQUIRED,
        optional = MBEDTLS_SSL_VERIFY_OPTIONAL,
    };

    enum class verify_flags : uint32_t
    {
        none = 0,
        allow_untrusted = 1u << 0u,
    };
    inline constexpr verify_flags operator|(verify_flags lhs, verify_flags rhs) {
        return static_cast<verify_flags>(static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
    }
    inline constexpr verify_flags operator&(verify_flags lhs, verify_flags rhs) {
        return static_cast<verify_flags>(static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
    }

    namespace detail {
        using mbedtls_ssl_context_ptr = g6::c_unique_ptr<mbedtls_ssl_context, mbedtls_ssl_init, mbedtls_ssl_free>;
        using mbedtls_ssl_config_ptr =
            g6::c_unique_ptr<mbedtls_ssl_config, mbedtls_ssl_config_init, mbedtls_ssl_config_free>;

        struct accept_sender;
        struct connect_sender;
        struct recv_sender;
        struct send_sender;

    }// namespace detail

    class async_socket : public net::async_socket
    {
    private:
#ifdef G6_SSL_DEBUG
        static void _mbedtls_debug(void *ctx, int level, const char *file, int line, const char *str) noexcept {
            //            auto ssl_ctx = static_cast<mbedtls_ssl_context*>(ctx);
            static constexpr std::string_view fmt = "{}:{}: {}";
            switch (level) {
                case 0:// shall not happen - no debug
                case 1:// error
                    spdlog::error(fmt, file, line, str);
                    break;
                case 3:// informational
                    spdlog::info(fmt, file, line, str);
                    break;
                case 2:// state change
                case 4:// verbose
                default:
                    spdlog::debug(fmt, file, line, str);
                    break;
            }
        }
#endif

        static int _mbedtls_verify_cert(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) noexcept {
            auto &self = *reinterpret_cast<ssl::async_socket *>(ctx);
            if ((*flags & MBEDTLS_X509_BADCERT_SKIP_VERIFY) && self.verify_mode_ == peer_verify_mode::none) {
                *flags &= MBEDTLS_X509_BADCERT_SKIP_VERIFY;
            }
            if ((self.verify_flags_ & ssl::verify_flags::allow_untrusted) != ssl::verify_flags::none) {
                *flags &= ~uint32_t(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCRL_NOT_TRUSTED);
            }
            return 0;
        }

        static int _mbedtls_send(void *ctx, const uint8_t *buf, size_t len) noexcept {
            auto &self = *static_cast<ssl::async_socket *>(ctx);
            if (self.to_send_ == std::tuple{len, buf}) {
                len = self.to_send_.actual_len;
                self.to_send_ = {};
                return len;
            } else {
                self.to_send_ = {len, buf};
                return MBEDTLS_ERR_SSL_WANT_WRITE;
            }
        }
        static int _mbedtls_recv(void *ctx, uint8_t *buf, size_t len) noexcept {
            abort();
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
        static int _mbedtls_recv_timeout(void *ctx, uint8_t *buf, size_t len, uint32_t timeout) noexcept {
            auto &self = *static_cast<ssl::async_socket *>(ctx);
            if (self.to_receive_ == std::tuple{len, buf}) {
                len = self.to_receive_.actual_len;
                self.to_receive_ = {};
                return len;
            } else {
                self.to_receive_ = {len, buf};
                assert(timeout == 0);
                return MBEDTLS_ERR_SSL_WANT_READ;
            }
        }

        template<bool const_ = false>
        struct ssl_buf {
            size_t len = 0;
            std::conditional_t<const_, const uint8_t *, uint8_t *> buf = nullptr;
            size_t actual_len = 0;

            operator bool() const noexcept { return len != 0 && buf != nullptr; }
            bool operator==(std::tuple<size_t, const uint8_t *> other) const noexcept {
                return len == std::get<0>(other) && buf == std::get<1>(other);
            }
        };

        enum class connection_mode
        {
            client,
            server
        };

        void init() {
            if (auto error = mbedtls_ssl_config_defaults(
                    ssl_config_.get(), mode_ == connection_mode::server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
                error != 0) {
                throw std::system_error{error, ssl::error_category, "mbedtls_ssl_config_defaults"};
            }

            mbedtls_ssl_conf_ca_chain(ssl_config_.get(), &ssl::context.ca_certs().chain(), nullptr);

            // default:
            //  - server: dont verify clients
            //  - client: verify server
            peer_verify_mode(verify_mode_);

            mbedtls_ssl_conf_rng(ssl_config_.get(), mbedtls_ctr_drbg_random, &ssl::context.drbg_context());

            if (certificate_) {
                assert(key_);
                if (auto error = mbedtls_ssl_conf_own_cert(ssl_config_.get(), &certificate_->chain(), &key_->ctx());
                    error != 0) {
                    throw std::system_error{error, ssl::error_category, "mbedtls_ssl_conf_own_cert"};
                }
            }

            _mbedtls_setup_callbacks();

            if (auto error = mbedtls_ssl_setup(ssl_context_.get(), ssl_config_.get()); error != 0) {
                throw std::system_error{error, ssl::error_category, "mbedtls_ssl_setup"};
            }
        }

        async_socket(io::context &io_context, int fd, connection_mode mode_, std::optional<ssl::certificate> cert,
                     std::optional<ssl::private_key> key)
            : net::async_socket{io_context, fd}, mode_{mode_}, certificate_{std::move(cert)}, key_{std::move(key)},
              verify_mode_{mode_ == connection_mode::server ? peer_verify_mode::none : peer_verify_mode::required} {
            init();
        }

        async_socket(net::async_socket &&raw_socket, connection_mode mode_, std::optional<ssl::certificate> cert,
                     std::optional<ssl::private_key> key)
            : net::async_socket{std::forward<net::async_socket>(raw_socket)}, mode_{mode_},
              certificate_{std::move(cert)}, key_{std::move(key)}, verify_mode_{mode_ == connection_mode::server
                                                                                    ? peer_verify_mode::none
                                                                                    : peer_verify_mode::required} {
            init();
        }

        friend struct detail::accept_sender;
        friend struct detail::connect_sender;
        friend struct detail::recv_sender;
        friend struct detail::send_sender;

        friend ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_server,
                                            net::ip_endpoint const &, ssl::certificate const &,
                                            ssl::private_key const &);

        friend auto tag_invoke(tag_t<net::async_connect>, ssl::async_socket &socket, const net::ip_endpoint &endpoint);

        friend ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_client);

        friend ssl::async_socket tag_invoke(tag_t<net::open_socket>, auto &ctx, ssl::detail::tags::tcp_client,
                                            ssl::certificate const &, ssl::private_key const &);

        void _mbedtls_setup_callbacks() {
            mbedtls_ssl_set_bio(ssl_context_.get(), this, &ssl::async_socket::_mbedtls_send,
                                &ssl::async_socket::_mbedtls_recv, &ssl::async_socket::_mbedtls_recv_timeout);

            mbedtls_ssl_conf_verify(ssl_config_.get(), &ssl::async_socket::_mbedtls_verify_cert, this);

#ifdef G6_SSL_DEBUG
            mbedtls_ssl_conf_dbg(ssl_config_.get(), &ssl::async_socket::_mbedtls_debug, this);
#endif
        }

        /** @brief Encrypt CPO
         *
         * @param socket
         * @return The encryption task
         */
        friend task<void> tag_invoke(tag_t<ssl::async_encrypt>, ssl::async_socket &socket) {
            auto &net_sock = static_cast<net::async_socket &>(socket);
            auto *ssl_ctx = socket.ssl_context_.get();
            while (!socket.encrypted_) {
                int result = mbedtls_ssl_handshake(ssl_ctx);
                if (result == MBEDTLS_ERR_SSL_WANT_READ) {
                    socket.to_receive_.actual_len = co_await net::async_recv(
                        net_sock, as_writable_bytes(span{socket.to_receive_.buf, socket.to_receive_.len}));
                } else if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    socket.to_send_.actual_len =
                        co_await net::async_send(net_sock, as_bytes(span{socket.to_send_.buf, socket.to_send_.len}));
                } else if (result == MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED) {
                    if (uint32_t flags = mbedtls_ssl_get_verify_result(ssl_ctx); flags != 0) {
                        char vrfy_buf[1024];
                        int res = mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
                        if (res < 0) {
                            throw std::system_error{res, ssl::error_category, "mbedtls_x509_crt_verify_info"};
                        } else if (res) {
                            throw std::system_error{MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED, ssl::error_category,
                                                    std::string{vrfy_buf, size_t(res - 1)}};
                        }
                    }
                    socket.encrypted_ = true;
                } else if (result != 0) {
                    throw std::system_error(result, ssl::error_category, "mbedtls_ssl_handshake");
                } else {
                    socket.encrypted_ = true;
                }
            }
        }

        /** @brief Send CPO
         *
         * @param data      Pointer to the data to send.
         * @param size      Size of the data pointed by @a data.
         * @return          Awaitable send task.
         * @co_return       The sent size.
         */
        friend task<size_t> tag_invoke(tag_t<net::async_send>, ssl::async_socket &socket,
                                       span<const std::byte> buffer) {
            assert(socket.encrypted_);
            auto &net_sock = static_cast<net::async_socket &>(socket);
            auto *ssl_ctx = socket.ssl_context_.get();
            size_t offset = 0;
            while (offset < buffer.size()) {
                int result = mbedtls_ssl_write(ssl_ctx, reinterpret_cast<const uint8_t *>(buffer.data()) + offset,
                                               buffer.size() - offset);
                if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    assert(socket.to_send_);// ensure buffer/len properly setup
                    socket.to_send_.actual_len =
                        co_await net::async_send(net_sock, as_bytes(span{socket.to_send_.buf, socket.to_send_.len}));
                } else if (result < 0) {
                    throw std::system_error(result, ssl::error_category, "mbedtls_ssl_write");
                } else {
                    offset += result;
                }
            }
            co_return offset;
        }

        /** @brief Recv CPO
         *
         * @param socket
         * @param buffer
         * @return
         */
        friend task<size_t> tag_invoke(tag_t<net::async_recv>, ssl::async_socket &socket, span<std::byte> buffer) {
            assert(socket.encrypted_);
            auto &net_sock = static_cast<net::async_socket &>(socket);
            auto *ssl_ctx = socket.ssl_context_.get();
            while (true) {
                auto result = mbedtls_ssl_read(ssl_ctx, reinterpret_cast<uint8_t *>(buffer.data()), buffer.size());
                if (result == MBEDTLS_ERR_SSL_WANT_READ) {
                    assert(socket.to_receive_);// ensure buffer/len properly setup
                    socket.to_receive_.actual_len = co_await net::async_recv(
                        net_sock, as_writable_bytes(span{socket.to_receive_.buf, socket.to_receive_.len}));
                } else if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                    co_return 0;
                } else if (result < 0) {
                    throw std::system_error(result, ssl::error_category, "mbedtls_ssl_read");
                } else {
                    co_return result;
                }
            }
        }

        friend task<std::tuple<async_socket, net::ip_endpoint>> tag_invoke(tag_t<net::async_accept>,
                                                                           ssl::async_socket &socket) {
            auto [in_sock, endpoint] = co_await net::async_accept(static_cast<net::async_socket &>(socket));
            ssl::async_socket ssl_sock{std::move(in_sock), ssl::async_socket::connection_mode::server,
                                       socket.certificate_, socket.key_};
            ssl_sock.host_name(socket.hostname_);
            ssl_sock.verify_flags_ = socket.verify_flags_;
            ssl_sock.verify_mode_ = socket.verify_mode_;
            co_await ssl::async_encrypt(ssl_sock);
            co_return std::make_tuple(std::move(ssl_sock), std::move(endpoint));
        }

        connection_mode mode_;
        std::optional<ssl::certificate> certificate_{};
        std::optional<ssl::private_key> key_{};
        detail::mbedtls_ssl_context_ptr ssl_context_ = detail::mbedtls_ssl_context_ptr::make();
        detail::mbedtls_ssl_config_ptr ssl_config_ = detail::mbedtls_ssl_config_ptr::make();
        bool encrypted_ = false;
        peer_verify_mode verify_mode_;
        verify_flags verify_flags_{};
        ssl_buf<> to_receive_{};
        ssl_buf<true> to_send_{};
        std::string hostname_;

    public:
        /// @cond
        // move ctor (must update callbacks)
        async_socket(async_socket &&other) noexcept
            : mode_{other.mode_}, certificate_{std::move(other.certificate_)}, key_{std::move(other.key_)},
              ssl_context_{std::move(other.ssl_context_)}, ssl_config_{std::move(other.ssl_config_)},
              encrypted_{other.encrypted_}, verify_mode_{other.verify_mode_}, verify_flags_{other.verify_flags_},
              to_receive_{other.to_receive_}, to_send_{other.to_send_}, net::async_socket{std::move(other)} {
            // update callbacks
            _mbedtls_setup_callbacks();
        }
        async_socket() = delete;

        virtual ~async_socket() noexcept = default;

        /** @brief Set peer verification mode.
		 *
		 * @param mode      The verification mode.
		 * @see ssl::peer_verify_mode
		 */
        void set_peer_verify_mode(ssl::peer_verify_mode mode) noexcept {
            verify_mode_ = mode;
            mbedtls_ssl_conf_authmode(ssl_config_.get(), int(mode));
        }

        auto get_peer_verify_mode() const noexcept { return verify_mode_; }

        void set_verify_flags(ssl::verify_flags flags) noexcept { verify_flags_ = verify_flags_ | flags; }
        void unset_verify_flags(ssl::verify_flags flags) noexcept { verify_flags_ = verify_flags_ & flags; }

        auto get_verify_flags() const noexcept { return verify_flags_; }

        /** @brief Set host name.
		 *
		 * @param host_name     The host name.
		 */
        void host_name(std::string_view host_name) noexcept {
            hostname_ = host_name;
            mbedtls_ssl_set_hostname(ssl_context_.get(), hostname_.data());
        }

        auto const &host_name() const noexcept { return hostname_; }
    };

}// namespace g6::ssl

#include <g6/ssl/impl/async_socket_impl.hpp>
