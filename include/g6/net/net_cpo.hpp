#pragma once

#include <g6/coro/async_generator.hpp>
#include <g6/coro/task.hpp>
#include <g6/coro/cpo/file.hpp>

#include <g6/tag_invoke>

#include <variant>
#include <span>

namespace g6::net {

    G6_MAKE_CPO(open_socket)

    G6_MAKE_CPO(async_accept)

    G6_MAKE_CPO(async_serve)

    constexpr struct _async_connect : g6::cpo<_async_connect> {
        using g6::cpo<_async_connect>::operator();

        template<tl::spec_of<std::variant> VarSock, typename... Args>
        decltype(auto) operator()(VarSock &var_sock, Args &&...args) const {
            return std::visit(
                [&]<typename Sock>(Sock &sock) { return this->tag_invoke(sock, std::forward<Args>(args)...); },
                var_sock);
        }
    } async_connect{};

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
        requires(g6::tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...>) auto
        operator()(Sock &sock, Args &&...args) const
            noexcept(g6::nothrow_tag_invocable_c<Concrete, Sock &, std::span<std::byte const>, Args &&...>) requires(
                sizeof...(Args) > 0) {
            return this->tag_invoke(sock, std::span<std::byte const, 0>{}, std::forward<Args>(args)...);
        }

        template<tl::spec_of<std::variant> VarSock, typename... Args>
        auto operator()(VarSock &var_sock, Args &&...args) const {
            return std::visit(
                [&]<typename Sock>(Sock &sock) { return this->tag_invoke(sock, std::forward<Args>(args)...); },
                var_sock);
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
            } while (has_pending_data(sock));
            co_return total_size;
        }

        template<typename Sock, typename... Args>
        requires g6::tag_invocable_c<Concrete, Sock &, std::span<std::byte>, Args &&...>
            async_generator<std::span<std::byte const>> operator()(Sock &sock, Args &&...args) const
            noexcept(g6::nothrow_tag_invocable_c<Concrete, Sock &, std::span<std::byte>, Args &&...>) {
            std::array<std::byte, 256> buffer;
            do {
                auto sz = co_await this->tag_invoke(
                    sock, as_writable_bytes(std::span{buffer.data(), buffer.size()}, std::forward<Args>(args)...));
                co_yield as_bytes(std::span{buffer.data(), sz});
            } while (has_pending_data(sock));
        }

        template<tl::spec_of<std::variant> VarSock, typename... Args>
        auto operator()(VarSock &var_sock, Args &&...args) const {
            return std::visit(
                [&]<typename Sock>(Sock &sock) { return this->tag_invoke(sock, std::forward<Args>(args)...); },
                var_sock);
        }
    };

    constexpr struct _async_recv : _async_recv_base<_async_recv> {
    } async_recv{};

    constexpr struct _async_recv_from : _async_recv_base<_async_recv_from> {
    } async_recv_from{};
    //
}// namespace g6::net
