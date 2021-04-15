#ifndef G6_NET_NET_CPO_HPP_
#define G6_NET_NET_CPO_HPP_

#include <g6/utils/cpo.hpp>

namespace g6::net {

    G6_CPO_DEF(open_socket)
    G6_CPO_DEF(async_accept)
    G6_CPO_DEF(async_connect)
    G6_CPO_DEF(async_send)
    G6_CPO_DEF(async_send_to)
    G6_CPO_DEF(async_recv)
    G6_CPO_DEF(async_recv_from)

    G6_CPO_DEF(has_pending_data)

}// namespace g6::net

#endif // G6_NET_NET_CPO_HPP_
