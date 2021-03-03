#pragma once

#include "ip_endpoint.hpp"
#include <unifex/tag_invoke.hpp>

namespace g6::net {
    namespace _io_cpo {
        template<typename Concrete>
        struct generic_cpo {
            template<typename Executor, typename... Args>
            auto operator()(
                Executor &&ex,
                Args &&...args) const
                noexcept(unifex::is_nothrow_tag_invocable_v<
                         Concrete,
                         Executor &&,
                         Args...>)
                    -> unifex::tag_invoke_result_t<
                        Concrete,
                        Executor &&,
                        Args...> {
                return unifex::tag_invoke(
                    *static_cast<Concrete const *>(this), std::forward<Executor>(ex), std::forward<Args>(args)...);
            }
        };
    }// namespace _io_cpo

#define G6_CPO_DEF(__name)                                         \
    namespace _io_cpo { inline const struct __name##_cpo : generic_cpo<__name##_cpo> { \
    } __name{}; } using _io_cpo::__name;

    G6_CPO_DEF(open_socket)
    G6_CPO_DEF(async_accept)
    G6_CPO_DEF(async_connect)
    G6_CPO_DEF(async_send)
    G6_CPO_DEF(async_send_to)
    G6_CPO_DEF(async_recv)
    G6_CPO_DEF(async_recv_from)

}// namespace g6::net
