#include <g6/ssl/async_socket.hpp>

#include <optional>

//#define G6_SSL_DEBUG

namespace g6::ssl {

    void async_socket::_mbedtls_debug(void *, int level, const char *file, int line, const char *str) noexcept {
#ifdef G6_SSL_DEBUG
        static constexpr std::string_view fmt = "[mbedtls-{}] - {}:{}: {}";
        switch (level) {
            case 0:// shall not happen - no debug
            case 1:// error
                fmt::print(fmt, "error", file, line, str);
                break;
            case 3:// informational
                fmt::print(fmt, "info", file, line, str);
                break;
            case 2:// state change
            case 4:// verbose
            default:
                fmt::print(fmt, "debug", file, line, str);
                break;
        }
#else
        (void) level;
        (void) file;
        (void) line;
        (void) str;
#endif
    }

    int async_socket::_mbedtls_verify_cert(void *ctx, mbedtls_x509_crt */*crt*/, int /*depth*/, uint32_t *flags) noexcept {
        auto &self = *reinterpret_cast<ssl::async_socket *>(ctx);
        if ((*flags & MBEDTLS_X509_BADCERT_SKIP_VERIFY) && self.verify_mode_ == peer_verify_mode::none) {
            *flags &= MBEDTLS_X509_BADCERT_SKIP_VERIFY;
        }
        if ((self.verify_flags_ & ssl::verify_flags::allow_untrusted) != ssl::verify_flags::none) {
            *flags &= ~uint32_t(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCRL_NOT_TRUSTED);
        }
        return 0;
    }

    int async_socket::_mbedtls_send(void *ctx, const uint8_t *buf, size_t len) noexcept {
        auto &self = *static_cast<ssl::async_socket *>(ctx);
        if (self.to_send_ == std::tuple{len, buf}) {
            len = self.to_send_.actual_len;
            self.to_send_ = {};
            return int(len);
        } else {
            self.to_send_ = {len, buf};
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
    }

    int async_socket::_mbedtls_recv(void */* ctx */, uint8_t * /*buf*/, size_t /*len*/) noexcept {
        abort();
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    int async_socket::_mbedtls_recv_timeout(void *ctx, uint8_t *buf, size_t len, uint32_t timeout) noexcept {
        (void) timeout;
        auto &self = *static_cast<ssl::async_socket *>(ctx);
        if (self.to_receive_ == std::tuple{len, buf}) {
            len = self.to_receive_.actual_len;
            self.to_receive_ = {};
            return int(len);
        } else {
            self.to_receive_ = {len, buf};
            assert(timeout == 0);
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
    }

    void async_socket::_mbedtls_setup_callbacks() {
        mbedtls_ssl_set_bio(ssl_context_.get(), this, &ssl::async_socket::_mbedtls_send,
                            &ssl::async_socket::_mbedtls_recv, &ssl::async_socket::_mbedtls_recv_timeout);

        mbedtls_ssl_conf_verify(ssl_config_.get(), &ssl::async_socket::_mbedtls_verify_cert, this);
        mbedtls_ssl_conf_dbg(ssl_config_.get(), &ssl::async_socket::_mbedtls_debug, this);
    }

    async_socket::async_socket(io::context &io_context, socket_handle::handle_t fd, net::socket_protocol proto, bool skip_on_success)
        : net::async_socket{io_context, fd, proto, skip_on_success} {
    }

    async_socket::async_socket(net::async_socket &&raw_socket, connection_mode mode,
                               std::optional<ssl::certificate> cert, std::optional<ssl::private_key> key)
        : net::async_socket{std::forward<net::async_socket>(raw_socket)}, mode_{mode},
          certificate_{std::move(cert)}, key_{std::move(key)}, verify_mode_{mode == connection_mode::server
                                                                                ? peer_verify_mode::none
                                                                                : peer_verify_mode::required} {
        init();
    }

    void async_socket::init() {
        if (auto error = mbedtls_ssl_config_defaults(
                ssl_config_.get(), mode_ == connection_mode::server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
            error != 0) {
            throw std::system_error{error, ssl::error_category, "mbedtls_ssl_config_defaults"};
        }

        mbedtls_ssl_conf_ca_chain(ssl_config_.get(), &detail::context::instance().ca_certs().chain(), nullptr);

        // default:
        //  - server: dont verify clients
        //  - client: verify server
        set_peer_verify_mode(verify_mode_);

        mbedtls_ssl_conf_rng(ssl_config_.get(), mbedtls_ctr_drbg_random, &detail::context::instance().drbg_context());

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

    void async_socket::listen(size_t count) {
        net::async_socket::listen(count);
        if (mode_ != connection_mode::server) {
            // we are server
            assert(mode_ == connection_mode::none);
            mode_ = connection_mode::server;
            init();
        }
    }

    task<std::tuple<async_socket, net::ip_endpoint>> tag_invoke(tag_t<net::async_accept>, ssl::async_socket &socket) {
        auto [in_sock, endpoint] = co_await net::async_accept(static_cast<net::async_socket &>(socket));
        ssl::async_socket ssl_sock{std::move(in_sock), ssl::async_socket::connection_mode::server, socket.certificate_,
                                   socket.key_};
        ssl_sock.host_name(socket.hostname_);
        ssl_sock.verify_flags_ = socket.verify_flags_;
        ssl_sock.verify_mode_ = socket.verify_mode_;
        co_await ssl::async_encrypt(ssl_sock);
        co_return std::make_tuple(std::move(ssl_sock), std::move(endpoint));
    }

    task<void> tag_invoke(tag_t<net::async_connect>, ssl::async_socket &socket, const net::ip_endpoint &endpoint) {
        assert(socket.mode_ == async_socket::connection_mode::none);
        socket.mode_ = async_socket::connection_mode::client;
        socket.init();
        co_await net::async_connect(static_cast<net::async_socket &>(socket), endpoint);
        co_await ssl::async_encrypt(socket);
    }

    task<void> tag_invoke(tag_t<ssl::async_encrypt>, ssl::async_socket &socket) {
        auto &net_sock = static_cast<net::async_socket &>(socket);
        auto *ssl_ctx = socket.ssl_context_.get();
        while (not socket.encrypted_) {
            int result = mbedtls_ssl_handshake(ssl_ctx);
            if (result == MBEDTLS_ERR_SSL_WANT_READ) {
                socket.to_receive_.actual_len =
                    co_await net::async_recv(net_sock, std::span{socket.to_receive_.buf, socket.to_receive_.len});
            } else if (result == MBEDTLS_ERR_SSL_WANT_WRITE) {
                socket.to_send_.actual_len =
                    co_await net::async_send(net_sock, std::span{socket.to_send_.buf, socket.to_send_.len});
            } else if (result == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
                if (uint32_t flags = mbedtls_ssl_get_verify_result(ssl_ctx); flags != 0) {
                    char vrfy_buf[1024];
                    int res = mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
                    if (res < 0) {
                        throw std::system_error{res, ssl::error_category, "mbedtls_x509_crt_verify_info"};
                    } else if (res) {
                        throw std::system_error{MBEDTLS_ERR_ECP_VERIFY_FAILED, ssl::error_category,
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

    task<size_t> tag_invoke(tag_t<net::async_recv>, ssl::async_socket &socket, std::span<std::byte> buffer) {
        assert(socket.encrypted_);
        auto &net_sock = static_cast<net::async_socket &>(socket);
        auto *ssl_ctx = socket.ssl_context_.get();
        while (true) {
            auto result = mbedtls_ssl_read(ssl_ctx, reinterpret_cast<uint8_t *>(buffer.data()), buffer.size());
            if (result == MBEDTLS_ERR_SSL_WANT_READ) {
                assert(socket.to_receive_);// ensure buffer/len properly setup
                socket.to_receive_.actual_len =
                    co_await net::async_recv(net_sock, std::span{socket.to_receive_.buf, socket.to_receive_.len});
            } else if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                co_return 0;
            } else if (result < 0) {
                throw std::system_error(result, ssl::error_category, "mbedtls_ssl_read");
            } else {
                co_return result;
            }
        }
        co_return 0;
    }

    task<size_t> tag_invoke(tag_t<net::async_send>, ssl::async_socket &socket, std::span<const std::byte> buffer) {
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
                    co_await net::async_send(net_sock, std::span{socket.to_send_.buf, socket.to_send_.len});
            } else if (result < 0) {
                throw std::system_error(result, ssl::error_category, "mbedtls_ssl_write");
            } else {
                offset += size_t(result);
            }
        }
        co_return offset;
    }

}// namespace g6::ssl

namespace g6::io {
    ssl::async_socket tag_invoke(tag_t<net::open_socket>, g6::io::context &ctx, net::proto::secure_tcp_t) {
#if G6_OS_WINDOWS
        auto [result, iocp_skip] = io::create_socket(net::proto::tcp, ctx.iocp_handle());
        if (result < 0) { throw std::system_error{static_cast<int>(::WSAGetLastError()), std::system_category()}; }
#else
        bool iocp_skip = false;
        int result = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (result < 0) { throw std::system_error{-errno, std::system_category()}; }
#endif
        return {ctx, result, net::proto::secure_tcp, iocp_skip};
    }
}// namespace g6::io
