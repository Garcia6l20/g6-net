/** @file g6/net/ssl/context.hpp
 * @author Sylvain Garcia <garcia.6l20@gmail.com>
 */
#pragma once

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>

#include <filesystem>

#include <g6/ssl/certificate.hpp>
#include <g6/ssl/error.hpp>
#include <g6/ssl/key_type.hpp>

#include <spdlog/spdlog.h>

#include <stdexcept>

namespace g6::ssl {
    template<key_type>
    class key;
    class async_socket;

    namespace detail {
        class context final {
            template<key_type>
            friend class ssl::key;
            friend class ssl::async_socket;

        private:
            explicit context() {
                mbedtls_debug_set_threshold(4);
                mbedtls_entropy_init(&entropy_context_);
                mbedtls_ctr_drbg_init(&ctr_drbg_context_);

                if (int error =
                        mbedtls_ctr_drbg_seed(&ctr_drbg_context_, mbedtls_entropy_func, &entropy_context_, nullptr, 0);
                    error != 0) {
                    throw std::system_error{error, ssl::error_category, "mbedtls_ctr_drbg_seed"};
                }

                // load system certificates
                for (auto path : {"/etc/ssl/certs", "/usr/lib/ssl/certs", "/usr/share/ssl", "/usr/local/ssl",
                                  "/var/ssl/certs", "/usr/local/ssl/certs", "/etc/openssl/certs", "/etc/ssl"}) {
                    if (std::filesystem::exists(path)) {
                        try {
                            certificate_chain_.load(path);
                        } catch (std::system_error const&error) {
                            // ignore - PK - Read/write of file failed
                            if (error.code().value() != 4) {
                                spdlog::error("ssl::context: failed to load system certificates at {} ({})", path, error.what());
                            }
                        }
                    }
                }
            }

            mbedtls_entropy_context &entropy_ctx() { return entropy_context_; }

            certificate certificate_chain_;
            mbedtls_entropy_context entropy_context_;
            mbedtls_ctr_drbg_context ctr_drbg_context_;

            [[nodiscard]] const certificate &ca_certs() const noexcept { return certificate_chain_; }
            [[nodiscard]] certificate &ca_certs() noexcept { return certificate_chain_; }

            [[nodiscard]] mbedtls_ctr_drbg_context &drbg_context() noexcept { return ctr_drbg_context_; }

        public:
            ~context() noexcept {
                mbedtls_entropy_free(&entropy_context_);
                mbedtls_ctr_drbg_free(&ctr_drbg_context_);
            }

            static auto &instance() {
                static context ctx{};
                return ctx;
            }
        };
    }// namespace detail

}// namespace g6::ssl
