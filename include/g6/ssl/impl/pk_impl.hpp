#pragma once

#include <g6/ssl/context.hpp>
#include <g6/ssl/error.hpp>
#include <g6/ssl/key.hpp>

namespace g6::ssl {
    template<key_type kt>
    size_t key<kt>::encrypt(std::span<std::byte const> plain_data, std::span<std::byte> encrypted_data) {
        size_t output_size = 0;
        if (auto err = mbedtls_pk_encrypt(ctx_.get(), reinterpret_cast<const uint8_t *>(plain_data.data()),
                                          plain_data.size_bytes(), reinterpret_cast<uint8_t *>(encrypted_data.data()),
                                          &output_size, encrypted_data.size_bytes(), mbedtls_ctr_drbg_random,
                                          &context.drbg_context());
            err != 0) {
            throw std::system_error(err, ssl::error_category);
        }
        return output_size;
    }

    template<key_type kt>
    size_t key<kt>::decrypt(std::span<std::byte const> encrypted_data, std::span<std::byte> plain_data) {
        size_t output_size = 0;
        if (auto err = mbedtls_pk_decrypt(ctx_.get(), reinterpret_cast<const uint8_t *>(encrypted_data.data()),
                                          encrypted_data.size_bytes(), reinterpret_cast<uint8_t *>(plain_data.data()),
                                          &output_size, plain_data.size_bytes(), mbedtls_ctr_drbg_random,
                                          &context.drbg_context());
            err != 0) {
            throw std::system_error(err, ssl::error_category);
        }
        return output_size;
    }
}// namespace g6::ssl
