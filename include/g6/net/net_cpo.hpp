#ifndef G6_NET_NET_CPO_HPP_
#define G6_NET_NET_CPO_HPP_

#include <g6/utils/cpo.hpp>

namespace g6::net {

    G6_CPO_DEF(open_socket, _net_cpo)
    G6_CPO_DEF(async_accept, _net_cpo)
    G6_CPO_DEF(async_connect, _net_cpo)
    G6_CPO_DEF(async_send, _net_cpo)
    G6_CPO_DEF(async_send_to, _net_cpo)
    G6_CPO_DEF(async_recv, _net_cpo)
    G6_CPO_DEF(async_recv_from, _net_cpo)

    G6_CPO_DEF(make_server, _net_cpo)

}// namespace g6::net

#endif // G6_NET_NET_CPO_HPP_
