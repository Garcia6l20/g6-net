/** @file g6/net/ssl/error.hpp
 * @author Sylvain Garcia <garcia.6l20@gmail.com>
 */
#pragma once

#include <mbedtls/error.h>

#include <array>
#include <system_error>
#include <string>

namespace g6::ssl
{
	inline struct error_category_t final : std::error_category {
        [[nodiscard]] const char* name() const noexcept final { return "ssl"; }
        [[nodiscard]] std::string message(int error) const noexcept final {
			std::array<char, 128> error_buf{};
            mbedtls_strerror(error, error_buf.data(), error_buf.size());
			return {error_buf.data(), error_buf.size()};
		}
	} error_category{};
}
