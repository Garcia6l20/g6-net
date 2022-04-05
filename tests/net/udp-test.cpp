#include <catch2/catch.hpp>

#include <fmt/format.h>

#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/net/ip_endpoint.hpp>
#include <g6/utils/scope_guard.hpp>

#include <g6/spawner.hpp>


TEST_CASE("udp tx/rx test", "[g6::net::udp]") {
    g6::io::context ctx{};
    std::stop_source stop_source{};
    using namespace std::chrono_literals;

    auto [rx_bytes, tx_bytes, _] = g6::spawner{[&]() -> g6::task<size_t> {
                    g6::scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
                    auto sock = g6::net::open_socket(ctx, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    std::array<std::byte, 64> buffer{};
                    sock.bind(*g6::net::ip_endpoint::from_string("127.0.0.1:4242"));
                    auto [bytes_received, from] = co_await g6::net::async_recv_from(
                        sock, std::as_writable_bytes(std::span{buffer.data(), buffer.size()}));
                    co_return bytes_received;
                }(),
                [&]() -> g6::task<size_t> {
                    auto sock = g6::net::open_socket(ctx, AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                    const char buffer[] = {"hello world !!!"};
                    co_await g6::schedule_after(ctx, 10ms);
                    auto bytes_sent = co_await g6::net::async_send_to(sock, as_bytes(std::span{buffer}),
                                                    *g6::net::ip_endpoint::from_string("127.0.0.1:4242"));
                    co_return bytes_sent;
                }(),
                g6::async_exec(ctx, stop_source.get_token())}
        .sync_wait();
    REQUIRE(tx_bytes != 0);
    REQUIRE(rx_bytes == tx_bytes);
}

// TEST_CASE("udp has_pending_data test", "[g6::net::udp]") {
//     io::context ctx{};
//     inplace_stop_source stop_source{};
//     auto sched = ctx.get_scheduler();

//     using namespace std::chrono_literals;

//     sync_wait(when_all(
//         [&]() -> task<void> {
//             scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
//             auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM);
//             std::array<std::byte, 64> buffer{};
//             sock.bind(*net::ip_endpoint::from_string("127.0.0.1:4242"));
//             REQUIRE_FALSE(net::has_pending_data(sock));
//             co_await schedule_at(sched, now(sched) + 10ms);
//             REQUIRE(net::has_pending_data(sock));
//         }(),
//         [&]() -> task<void> {
//             auto sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM);
//             const char buffer[] = {"hello world !!!"};
//             auto bytes_sent = co_await g6::net::async_send_to(sock, as_bytes(span{buffer}),
//                                                               *g6::net::ip_endpoint::from_string("127.0.0.1:4242"));
//         }(),
//         [&]() -> task<void> {
//             ctx.run(stop_source.get_token());
//             co_return;
//         }()));
// }

//
//TEST_CASE("udp tx/rx coroless test", "[g6::net::udp]") {
//
//    io::context ctx{};
//    inplace_stop_source stop_source{};
//    std::thread t{[&] { ctx.run(stop_source.get_token()); }};
//    scope_guard stop_on_exit = [&]() noexcept {
//        stop_source.request_stop();
//        t.join();
//    };
//
//    char server_buffer[1024];
//    auto server_sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM);
//    server_sock.bind(*net::ip_endpoint::from_string("127.0.0.1:0"));
//    const auto server_endpoint = *server_sock.local_endpoint();
//
//    const char client_buffer[] = {"hello world !!!"};
//    char client_rx_buffer[1024];
//    auto client_sock = net::open_socket(ctx, AF_INET, SOCK_DGRAM);
//    client_sock.bind(*net::ip_endpoint::from_string("127.0.0.1:0"));
//
//    fmt::print("server endpoint: {}\n", server_endpoint.to_string());
//    fmt::print("client endpoint: {}\n", client_sock.local_endpoint()->to_string());
//
//    sync_wait(
//        when_all(let(net::async_recv_from(server_sock, as_writable_bytes(span{server_buffer})),
//                     [&](size_t bytes, auto from) {
//                         fmt::print("server received {} bytes from {}\n", bytes, from.to_string());
//                         return net::async_send_to(server_sock, as_bytes(span{server_buffer, bytes}), std::move(from));
//                     }),
//                 let(net::async_send_to(client_sock, as_bytes(span{client_buffer}), server_endpoint),
//                     [&](size_t bytes) {
//                         fmt::print("sent {} bytes\n", bytes);
//                         return net::async_recv(client_sock, as_writable_bytes(span{client_rx_buffer})) |
//                                transform([](size_t bytes) {
//                                    fmt::print("client received {} bytes\n", bytes);
//                                    return bytes;
//                                });
//                     })) |
//        transform([](auto server_res, auto client_res) {
//            size_t server_bytes = std::get<0>(std::get<0>(server_res));
//            size_t client_bytes = std::get<0>(std::get<0>(client_res));
//            fmt::print("result: {}/{}\n", client_bytes, server_bytes);
//            REQUIRE(client_bytes == server_bytes);
//        }));
//}
