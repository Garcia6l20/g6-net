/** @file g6/net/ssl/concepts.hpp
 * @author Sylvain Garcia <garcia.6l20@gmail.com>
 */
#pragma once

#include <g6/net/concepts.hpp>

namespace g6::ssl
{
    // clang-format off
	template <typename T>
	concept is_socket = g6::sslis_socket<T> and requires (T v)
    {
        { v.encrypt(std::declval<cancellation_token>()) } -> awaitable;
    };
    // clang-format on
}
