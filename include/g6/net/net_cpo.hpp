#ifndef G6_NET_NET_CPO_HPP_
#define G6_NET_NET_CPO_HPP_

#include <g6/tag_invoke.hpp>

namespace g6::net {

    G6_MAKE_CPO(open_socket)

    G6_MAKE_CPO(async_accept)
    G6_MAKE_CPO(async_connect)
    G6_MAKE_CPO(async_send)
    G6_MAKE_CPO(async_send_to)
    G6_MAKE_CPO(async_recv)
    G6_MAKE_CPO(async_recv_from)

    G6_MAKE_CPO(pending_bytes)
    G6_MAKE_CPO(has_pending_data)

}// namespace g6::net

#endif// G6_NET_NET_CPO_HPP_
