#include <catch2/catch.hpp>


#include <g6/io/context.hpp>

#include <g6/net/async_socket.hpp>

#include <g6/scope_guard.hpp>
#include <g6/sync_wait.hpp>

using namespace g6;

class counted_stop_source {
public:
    counted_stop_source(size_t threshold = 0) noexcept : threshold_{threshold} {}

    auto get_token() const noexcept { return stop_source_.get_token(); }
    void request_stop() noexcept {
        if (++count_ >= threshold_) {//
            stop_source_.request_stop();
        }
    }
    auto &operator++() noexcept {
        ++threshold_;
        return *this;
    }

    auto stop_requested() const noexcept { return stop_source_.stop_requested(); }

    auto threshold() const noexcept { return threshold_; }

private:
    std::stop_source stop_source_;
    size_t threshold_;
    size_t count_ = 0;
};

TEST_CASE("udp tx/rx test", "[g6::net::udp]") {
    io::context ctx{};
    std::stop_source stop_source{};
    using namespace std::chrono_literals;

    auto [rx_bytes, tx_bytes, _] = sync_wait(
        [&]() -> task<size_t> {
            scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
            auto sock = net::open_socket(ctx, net::proto::udp);
            std::array<std::byte, 64> buffer{};
            sock.bind(*g6::from_string<net::ip_endpoint>("127.0.0.1:4242"));
            auto [bytes_received, from] =
                co_await net::async_recv_from(sock, std::as_writable_bytes(std::span{buffer.data(), buffer.size()}));
            co_return bytes_received;
        }(),
        [&]() -> task<size_t> {
            auto sock = net::open_socket(ctx, net::proto::udp);
            const char buffer[] = {"hello world !!!"};
            co_await schedule_after(ctx, 10ms);
            auto bytes_sent = co_await net::async_send_to(sock, as_bytes(std::span{buffer}),
                                                          *from_string<net::ip_endpoint>("127.0.0.1:4242"));
            co_return bytes_sent;
        }(),
        async_exec(ctx, stop_source.get_token()));
    REQUIRE(tx_bytes != 0);
    REQUIRE(rx_bytes == tx_bytes);
}

TEST_CASE("udp has_pending_data test", "[g6::net::udp]") {
    io::context ctx{};
    std::stop_source stop_source{};

    using namespace std::chrono_literals;

    sync_wait(
        [&]() -> task<void> {
            scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
            auto sock = net::open_socket(ctx, net::proto::udp);
            std::array<std::byte, 64> buffer{};
            sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:4242"));
            REQUIRE_FALSE(net::has_pending_data(sock));
            co_await schedule_after(ctx, 10ms);
            REQUIRE(net::pending_bytes(sock) == 16);
        }(),
        [&]() -> task<void> {
            auto sock = net::open_socket(ctx, net::proto::udp);
            const char buffer[] = {"hello world !!!"};
            auto bytes_sent = co_await net::async_send_to(sock, std::as_bytes(std::span{buffer}),
                                                          *from_string<net::ip_endpoint>("127.0.0.1:4242"));
        }(),
        async_exec(ctx, stop_source.get_token()));
}

TEST_CASE("udp reuse address", "[g6::net::udp]") {
    io::context ctx{};
    counted_stop_source stop_source{};
    using namespace std::chrono_literals;

    auto listener = [&](size_t id) -> task<size_t> {
        scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
        ++stop_source;
        auto sock = net::open_socket(ctx, net::proto::udp);
        sock.setopt<net::socket_options::reuse_address>(true);
        REQUIRE(sock.getopt<net::socket_options::reuse_address>() == true);
        sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:4242"));
        std::array<std::byte, 64> buffer{};
        fmt::print("listener {} listening...\n", id);
        auto [bytes_received, from] =
            co_await net::async_recv_from(sock, std::as_writable_bytes(std::span{buffer.data(), buffer.size()}));
        fmt::print("listener {} received {} bytes\n", id, bytes_received);
        co_return bytes_received;
    };

    auto [rx_bytes1, rx_bytes2, tx_bytes, _] = sync_wait(
        listener(1), listener(2),
        [&]() -> task<size_t> {
            auto sock = net::open_socket(ctx, net::proto::udp);
            const char buffer[] = {"hello world !!!"};
            const auto ep = *from_string<net::ip_endpoint>("127.0.0.1:4242");
            const auto bytes = as_bytes(std::span{buffer});
            size_t bytes_sent = 0;
            for (size_t ii = 0; ii < stop_source.threshold(); ++ii) {
                co_await schedule_after(ctx, 10ms);
                bytes_sent = co_await net::async_send_to(sock, bytes, ep);
                fmt::print("{} bytes sent...\n", bytes_sent);
            }
            co_return bytes_sent;
        }(),
        async_exec(ctx, stop_source.get_token()));
    REQUIRE(tx_bytes != 0);
    REQUIRE(rx_bytes1 == tx_bytes);
    REQUIRE(rx_bytes2 == tx_bytes);
}


TEST_CASE("udp multicast", "[g6::net::udp]") {
    io::context ctx{};
    counted_stop_source stop_source{};
    using namespace std::chrono_literals;

    auto listener = [&]() -> task<size_t> {
        scope_guard _ = [&]() noexcept { stop_source.request_stop(); };
        ++stop_source;
        try {
            auto sock = net::open_socket(ctx, net::proto::udp);
            sock.setopt<net::socket_options::reuse_address>(true);
            sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:4242"));
            sock.setopt<net::socket_options::ip::add_membership>(from_string<net::ip_address>("224.0.0.1")->to_ipv4(),
                                                                 sock.local_endpoint()->address().to_ipv4());
            sock.setopt<net::socket_options::ip::multicast_loop>(true);
            std::array<std::byte, 64> buffer{};
            fmt::print("listening...\n");
            auto [bytes_received, from] =
                co_await net::async_recv_from(sock, std::as_writable_bytes(std::span{buffer.data(), buffer.size()}));
            fmt::print("listener received {} bytes\n", bytes_received);
            co_return bytes_received;
        } catch (std::exception const &error) {//
            FAIL(error.what());
        }
    };

    auto [rx_bytes, tx_bytes, _] = sync_wait(
        listener(),
        [&]() -> task<size_t> {
            try {
                auto sock = net::open_socket(ctx, net::proto::udp);
                sock.bind(*from_string<net::ip_endpoint>("127.0.0.1:0"));
                const char buffer[] = {"hello world !!!"};
                const auto ep = *from_string<net::ip_endpoint>("224.0.0.1:4242");
                const auto bytes = as_bytes(std::span{buffer});
                co_await schedule_after(ctx, 100ms);
                auto bytes_sent = co_await net::async_send_to(sock, bytes, ep);
                fmt::print("{} bytes sent...\n", bytes_sent);
                co_return bytes_sent;
            } catch (std::exception const &error) {//
                FAIL(error.what());
            }
        }(),
        async_exec(ctx, stop_source.get_token()));
    REQUIRE(tx_bytes != 0);
    REQUIRE(rx_bytes == tx_bytes);
}
