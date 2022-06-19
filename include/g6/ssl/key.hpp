/** @file g6/ssl/key.hpp
 * @author Sylvain Garcia <garcia.6l20@gmail.com>
 */
#pragma once

#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>


#include <g6/ssl/error.hpp>
#include <g6/ssl/key_type.hpp>
#include <g6/utils/c_ptr.hpp>

#include <filesystem>
#include <span>

namespace g6::ssl {
    namespace detail {
        using mbedtls_pk_context_ptr = g6::c_shared_ptr<mbedtls_pk_context, mbedtls_pk_init, mbedtls_pk_free>;
    }

    template<key_type type_>
    class key {
    public:
        explicit key() noexcept = default;

        template<typename T>
        explicit key(std::span<T> data, std::string_view passphrase = {}) : key{} {
            if constexpr (type_ == key_type::private_) {
                if (auto error = mbedtls_pk_parse_key(
                        ctx_.get(), reinterpret_cast<const unsigned char *>(data.data()), data.size_bytes(),
                        reinterpret_cast<const unsigned char *>(passphrase.empty() ? nullptr : passphrase.data()),
                        passphrase.size());
                    error) {
                    throw std::system_error{error, ssl::error_category, "mbedtls_pk_parse_key"};
                }
            } else {
                if (auto error = mbedtls_pk_parse_public_key(
                        ctx_.get(), reinterpret_cast<const unsigned char *>(data.data()), data.size_bytes());
                    error) {
                    throw std::system_error{error, ssl::error_category, "mbedtls_pk_parse_public_key"};
                }
            }
        }

        [[nodiscard]] mbedtls_pk_context &ctx() { return *ctx_; }

        size_t encrypt(std::span<std::byte const> plain_data, std::span<std::byte> encrypted_data);
        size_t decrypt(std::span<std::byte const> encrypted_data, std::span<std::byte> plain_data);

    private:
        detail::mbedtls_pk_context_ptr ctx_ = detail::mbedtls_pk_context_ptr::make();
    };
    class private_key final : public key<key_type::private_> {
        using key<key_type::private_>::key;
    };
    class public_key final : public key<key_type::public_> {
        using key<key_type::public_>::key;
    };
}// namespace g6::ssl

#include <g6/ssl/impl/pk_impl.hpp>
