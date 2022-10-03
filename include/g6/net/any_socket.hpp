#pragma once

#include <g6/net/async_socket.hpp>
#include <g6/ssl/async_socket.hpp>

#include <variant>

namespace g6::net
{
    using any_socket = std::variant<net::async_socket, ssl::async_socket>;
} // namespace g6::net
