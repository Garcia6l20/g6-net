#pragma once

#include <g6/coro/task.hpp>
#include <g6/tag_invoke>

#include <span>

namespace g6::net {

    G6_MAKE_CPO(open_socket)

    G6_MAKE_CPO(pending_bytes)
    G6_MAKE_CPO(has_pending_data)

    G6_MAKE_CPO(async_close)

    G6_MAKE_CPO(async_accept)
    G6_MAKE_CPO(async_connect)

    template<typename Concrete>
    struct _async_send_base : g6::cpo<Concrete> {
        using g6::cpo<Concrete>::operator();

        template<typename Sock, typename T, size_t extent, typename... Args>
        requires g6::tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...> auto
        operator()(Sock &sock, std::span<T const, extent> buffer, Args &&...args) const
            noexcept(g6::nothrow_tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...>) {
            return this->tag_invoke(sock, as_bytes(buffer), std::forward<Args>(args)...);
        }

        template<typename Sock, typename Container, typename... Args>
        requires g6::tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...> auto
        operator()(Sock &sock, Container const &cont, Args &&...args) const noexcept(
            g6::nothrow_tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...>) requires(requires {
            {cont.data()};
            {cont.size()};
        }) {
            return this->tag_invoke(sock, as_bytes(std::span{cont.data(), cont.size()}), std::forward<Args>(args)...);
        }

        // some protocols can send message with empty data thus, this template function will be used
        template<typename Sock, typename... Args>
        requires g6::tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...> auto
        operator()(Sock &sock, Args &&...args) const noexcept(
            g6::nothrow_tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...>) requires(sizeof...(Args) > 0) {
            return this->tag_invoke(sock, std::span<std::byte const, 0>{}, std::forward<Args>(args)...);
        }
    };

    constexpr struct _async_send : _async_send_base<_async_send> {
    } async_send{};

    constexpr struct _async_send_to : _async_send_base<_async_send_to> {
    } async_send_to{};

    template<typename Concrete>
    struct _async_recv_base : g6::cpo<Concrete> {
        using g6::cpo<Concrete>::operator();

        template<typename Sock, typename T, size_t extent, typename... Args>
        requires g6::tag_invocable_c<Concrete, Sock &, std::span<std::byte>, Args &&...> auto
        operator()(Sock &sock, std::span<T, extent> buffer, Args &&...args) const
            noexcept(g6::nothrow_tag_invocable_c<Concrete, Sock &, std::span<std::byte>, Args &&...>) {
            return this->tag_invoke(sock, as_writable_bytes(buffer), std::forward<Args>(args)...);
        }

        template<typename Sock, typename Container, typename... Args>
        requires g6::tag_invocable_c<Concrete, Sock &, std::span<std::byte>, Args &&...> task<size_t>
        operator()(Sock &sock, std::back_insert_iterator<Container> cont, Args &&...args) const
            noexcept(g6::nothrow_tag_invocable_c<Concrete, Sock &, std::span<std::byte>, Args &&...>) {
            std::array<typename Container::value_type, 256> buffer;
            size_t total_size = 0;
            do {
                auto sz = co_await this->tag_invoke(
                    sock, as_writable_bytes(std::span{buffer.data(), buffer.size()}, std::forward<Args>(args)...));
                std::copy(std::begin(buffer), std::begin(buffer) + sz, cont);
                total_size += sz;
            } while (net::has_pending_data(sock));
            co_return total_size;
        }
    };

    constexpr struct _async_recv : _async_recv_base<_async_recv> {
    } async_recv{};

    constexpr struct _async_recv_from : _async_recv_base<_async_recv_from> {
    } async_recv_from{};
    //
}// namespace g6::net
