#pragma once

#include "ip_endpoint.hpp"
#include <unifex/tag_invoke.hpp>

namespace g6::net {
    namespace _io_cpo {

        inline const struct open_socket_cpo {
            template<typename Executor>
            auto operator()(Executor &&executor, int domain, int type, int proto = 0) const
            noexcept(unifex::is_nothrow_tag_invocable_v<
                     open_socket_cpo,
                Executor,
                int, int, int>)
            -> unifex::tag_invoke_result_t<
                open_socket_cpo,
                Executor,
                int, int, int> {
                return unifex::tag_invoke(*this, (Executor &&) executor, domain, type, proto);
            }
        } open_socket{};

        inline const struct async_recv_cpo {
            template<typename ForwardReader, typename BufferSequence>
            auto operator()(
                ForwardReader &socket,
                BufferSequence &&bufferSequence) const
                noexcept(unifex::is_nothrow_tag_invocable_v<
                         async_recv_cpo,
                         ForwardReader &,
                         BufferSequence>)
                    -> unifex::tag_invoke_result_t<
                        async_recv_cpo,
                        ForwardReader &,
                        BufferSequence> {
                return unifex::tag_invoke(
                    *this, socket, (BufferSequence &&) bufferSequence);
            }
        } async_recv{};

        inline const struct async_send_cpo {
            template<typename ForwardReader, typename BufferSequence>
            auto operator()(
                ForwardReader &socket,
                BufferSequence &&bufferSequence) const
            noexcept(unifex::is_nothrow_tag_invocable_v<
                async_send_cpo,
                ForwardReader &,
                BufferSequence>)
            -> unifex::tag_invoke_result_t<
                async_send_cpo,
                ForwardReader &,
                BufferSequence> {
                return unifex::tag_invoke(
                    *this, socket, (BufferSequence &&) bufferSequence);
            }
        } async_send{};

        inline const struct async_recv_from_cpo {
            template<typename ForwardReader, typename BufferSequence>
            auto operator()(
                ForwardReader &socket,
                BufferSequence &&bufferSequence) const
            noexcept(unifex::is_nothrow_tag_invocable_v<
                async_recv_from_cpo,
                ForwardReader &,
                BufferSequence>)
            -> unifex::tag_invoke_result_t<
                async_recv_from_cpo,
                ForwardReader &,
                BufferSequence> {
                return unifex::tag_invoke(
                    *this, socket, (BufferSequence &&) bufferSequence);
            }
        } async_recv_from{};

        inline const struct async_send_to_cpo {
            template<typename ForwardReader, typename BufferSequence, typename Endpoint>
            auto operator()(
                ForwardReader &socket,
                BufferSequence &&bufferSequence,
                Endpoint &&endpoint) const
            noexcept(unifex::is_nothrow_tag_invocable_v<
                async_send_to_cpo,
                ForwardReader &,
                BufferSequence,
                Endpoint>)
            -> unifex::tag_invoke_result_t<
                async_send_to_cpo,
                ForwardReader &,
                BufferSequence,
                Endpoint> {
                return unifex::tag_invoke(
                    *this, socket, (BufferSequence &&) bufferSequence, (Endpoint &&) endpoint);
            }
        } async_send_to{};
    }// namespace _io_cpo

    using _io_cpo::open_socket;
    using _io_cpo::async_recv;
    using _io_cpo::async_recv_from;
    using _io_cpo::async_send;
    using _io_cpo::async_send_to;
}// namespace g6::net
