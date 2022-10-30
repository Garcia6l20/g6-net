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
            explicit context();

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
