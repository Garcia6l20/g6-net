#include <catch2/catch.hpp>

#include <cert.hpp>
#include <g6/ssl/key.hpp>

using namespace g6;

TEST_CASE("g6::ssl::key encrypt/decrypt", "[g6::ssl]") {
    ssl::private_key pk{key};
    std::string_view data_in{"hello world !"};
    std::array<char, 512> encrypted_data{};
    auto encrypted_size = pk.encrypt(std::as_bytes(std::span{data_in.data(), data_in.size()}),
                                     std::as_writable_bytes(std::span{encrypted_data}));
    std::array<char, 512> decrypted_data{};
    auto decrypted_size = pk.decrypt(std::as_bytes(std::span{encrypted_data.data(), encrypted_size}),
                                     std::as_writable_bytes(std::span{decrypted_data}));
    auto ok =
        std::string_view{data_in.data(), data_in.size()} == std::string_view{decrypted_data.data(), decrypted_size};
    REQUIRE(ok);
}
