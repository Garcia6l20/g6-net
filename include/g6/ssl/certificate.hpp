/** @file g6/ssl/certificate.hpp
 * @author Sylvain Garcia <garcia.6l20@gmail.com>
 */
#pragma once

#include <mbedtls/x509_crt.h>

#include <fmt/format.h>

#include <filesystem>
#include <g6/ssl/error.hpp>
#include <g6/utils/c_ptr.hpp>

#include <span>

namespace g6::ssl
{
	namespace detail
	{
		using mbedtls_x509_crt_ptr =
			g6::c_shared_ptr<mbedtls_x509_crt, mbedtls_x509_crt_init, mbedtls_x509_crt_free>;
	}
	class certificate final
	{
	public:
		certificate() noexcept = default;

		certificate(const certificate& other)
		{
			load(other.chain());
		}

        certificate(certificate &&) = default;

		explicit certificate(std::string_view path)
		{
			load(path);
		}

		template<typename T>
        explicit certificate(std::span<T> data)
        {
            load(data);
        }

        void load(mbedtls_x509_crt const& other)
        {
            load(std::span{ other.raw.p, other.raw.len });
            auto next = other.next;
            while (next) {
                load(std::span{next->raw.p, next->raw.len});
                next = next->next;
            }
		}

		template<typename T>
		void load(std::span<T> data)
		{
			if (auto error = mbedtls_x509_crt_parse(
					crt_.get(), reinterpret_cast<const uint8_t*>(data.data()), data.size_bytes());
				error != 0)
			{
				throw std::system_error{ error,
										 ssl::error_category,
										 "mbedtls_x509_crt_parse_path" };
			}
		}

		void load(std::string_view path)
		{
			if (std::filesystem::is_directory(path))
			{
				if (auto error = mbedtls_x509_crt_parse_path(crt_.get(), path.data()); error != 0)
				{
					throw std::system_error{ error,
											 ssl::error_category,
											 "mbedtls_x509_crt_parse_path" };
				}
			}
			else
			{
				if (auto error = mbedtls_x509_crt_parse_file(crt_.get(), path.data()); error != 0)
				{
					throw std::system_error{ error,
											 ssl::error_category,
											 "mbedtls_x509_crt_parse_file" };
				}
			}
		}

		[[nodiscard]] mbedtls_x509_crt const & chain() const {
			return *crt_;
		}

        [[nodiscard]] mbedtls_x509_crt & chain() {
            return *crt_;
        }

	private:
        detail::mbedtls_x509_crt_ptr crt_ = detail::mbedtls_x509_crt_ptr::make();
	};
}  // namespace g6::ssl
