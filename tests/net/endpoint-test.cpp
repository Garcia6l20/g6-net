#include "g6/net/ipv4_endpoint.hpp"
#include <catch2/catch.hpp>

#include <g6/net/ip_endpoint.hpp>

using namespace g6;

TEST_CASE("g6::net::ip_endpoint", "[g6][net]") {
    SECTION("ipv4 address from_string") {
        auto addr = g6::from_string<net::ipv4_address>("127.0.0.1");
        REQUIRE(addr);
        g6::print("ipv4 address: {}\n", *addr);
    }
    SECTION("ipv6 address from_string") {
        auto addr = g6::from_string<net::ipv6_address>("0000:0000:0000:0000:0000:0000:0000:0001");
        REQUIRE(addr);
        g6::print("ipv6 address: {}\n", *addr);
    }
    SECTION("ip address from_string") {
        auto addr = g6::from_string<net::ip_address>("127.0.0.1");
        REQUIRE(addr);
        g6::print("ip address: {}\n", *addr);
        addr = g6::from_string<net::ip_address>("::1");
        REQUIRE(addr);
        g6::print("ip address: {}\n", *addr);
    }
    SECTION("ipv4 endpoint from_string") {
        auto ep = g6::from_string<net::ipv4_endpoint>("127.0.0.1:4242");
        REQUIRE(ep);
        g6::print("ipv4 endpoint: {}\n", *ep);
    }
    SECTION("ipv6 endpoint from_string") {
        auto ep = g6::from_string<net::ipv6_endpoint>("[::1]:4242");
        REQUIRE(ep);
        g6::print("ipv6 endpoint: {}\n", *ep);
    }
    SECTION("ip endpoint from_string") {
        auto ep = g6::from_string<net::ip_endpoint>("127.0.0.1:4242");
        REQUIRE(ep);
        g6::print("ip endpoint: {}\n", *ep);
        ep = g6::from_string<net::ip_endpoint>("[::1]:4242");
        REQUIRE(ep);
        g6::print("ip endpoint: {}\n", *ep);
    }
}
