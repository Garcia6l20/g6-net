#ifndef G6_NET_IMPL_SOCKET_OPTION_HPP_
#define G6_NET_IMPL_SOCKET_OPTION_HPP_

#include <cxxcoro/net/socket.hpp>
#include <cxxcoro/net/socket_options.hpp>

#include <source_location>

namespace g6::net
{
    template <int so_level, int opt_name, typename UserT, typename ImplT>
    void simple_option<so_level, opt_name, UserT, ImplT>::operator()(socket& sock)
    {
        auto value = static_cast<ImplT>(this->value_);
        if (setsockopt(sock.native_handle(), so_level, opt_name, &value, sizeof(value)) < 0)
        {
			using namespace std::literals;
            throw std::system_error{ errno,
                                     std::system_category(),
                                     "Cannot set socket option: "s + std::source_location::current().function_name() };
        }
    }
}  // namespace g6::net::socket_options

#endif // G6_NET_IMPL_SOCKET_OPTION_HPP_
