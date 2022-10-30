#include <g6/ssl/certificate.hpp>
#include <g6/coro/generators.hpp>

#include <mbedtls/error.h>
#include <spdlog/spdlog.h>

namespace g6::ssl {

    generator<std::filesystem::path const&> walk(std::filesystem::path path) {
        for (auto const& entry : std::filesystem::directory_iterator(path)) {
            if (std::filesystem::is_directory(entry.path())) {
                auto g = walk(entry.path());
                for (auto it = std::begin(g); it != std::end(g); ++it) {
                    co_yield *it;
                }
            }
            co_yield entry.path();
        }
    }
    
    void certificate::load(std::string_view path) {
        if (std::filesystem::is_directory(path)) {
            for (const auto &f : walk(path) | filter([](auto const &f) { return f.filename().has_extension(); })) {
                if (auto error = mbedtls_x509_crt_parse_file(crt_.get(), f.c_str()); error != 0) {
                    if (error == MBEDTLS_ERR_X509_INVALID_FORMAT) {
                        spdlog::debug("certificate::load: not loading {}: invalid format", f.c_str());
                    } else {
                        throw std::system_error{error, ssl::error_category, format("mbedtls_x509_crt_parse_file: {}", f.filename().c_str())};
                    }
                }
            }
        } else {
            if (auto error = mbedtls_x509_crt_parse_file(crt_.get(), path.data()); error != 0) {
                throw std::system_error{error, ssl::error_category, "mbedtls_x509_crt_parse_file"};
            }
        }
    }
}
