#include <g6/ssl/context.hpp>

namespace g6::ssl::detail {

    context::context() {
        mbedtls_debug_set_threshold(4);
        mbedtls_entropy_init(&entropy_context_);
        mbedtls_ctr_drbg_init(&ctr_drbg_context_);

        if (int error = mbedtls_ctr_drbg_seed(&ctr_drbg_context_, mbedtls_entropy_func, &entropy_context_, nullptr, 0);
            error != 0) {
            throw std::system_error{error, ssl::error_category, "mbedtls_ctr_drbg_seed"};
        }

        // load system certificates
        for (auto path : {"/etc/ssl/certs", "/usr/lib/ssl/certs", "/usr/share/ssl", "/usr/local/ssl", "/var/ssl/certs",
                          "/usr/local/ssl/certs", "/etc/openssl/certs", "/etc/ssl"}) {
            if (std::filesystem::exists(path)) {
                try {
                    certificate_chain_.load(path);
                } catch (std::system_error const &error) {
                    // ignore - PK - Read/write of file failed
                    if (error.code().value() != 4) {
                        spdlog::error("ssl::context: failed to load system certificates at {} ({})", path,
                                      error.what());
                    }
                }
            }
        }
    }

}// namespace g6::ssl
