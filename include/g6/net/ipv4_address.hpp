#pragma once

#include <g6/format.hpp>
#include <g6/from_string.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace g6::net {
    class ipv4_address {
        using bytes_t = std::uint8_t[4];

    public:
        constexpr ipv4_address() : m_bytes{0, 0, 0, 0} {}

        explicit constexpr ipv4_address(std::uint32_t integer)
            : m_bytes{static_cast<std::uint8_t>(integer >> 24), static_cast<std::uint8_t>(integer >> 16),
                      static_cast<std::uint8_t>(integer >> 8), static_cast<std::uint8_t>(integer)} {}

        explicit constexpr ipv4_address(const std::uint8_t (&bytes)[4])
            : m_bytes{bytes[0], bytes[1], bytes[2], bytes[3]} {}

        explicit constexpr ipv4_address(std::uint8_t b0, std::uint8_t b1, std::uint8_t b2, std::uint8_t b3)
            : m_bytes{b0, b1, b2, b3} {}

        [[nodiscard]] constexpr const bytes_t &bytes() const { return m_bytes; }

        [[nodiscard]] constexpr std::uint32_t to_integer() const {
            return std::uint32_t(m_bytes[0]) << 24 | std::uint32_t(m_bytes[1]) << 16 | std::uint32_t(m_bytes[2]) << 8
                 | std::uint32_t(m_bytes[3]);
        }

        static constexpr ipv4_address loopback() { return ipv4_address(127, 0, 0, 1); }

        [[nodiscard]] constexpr bool is_loopback() const { return m_bytes[0] == 127; }

        [[nodiscard]] constexpr bool is_private_network() const {
            return m_bytes[0] == 10 || (m_bytes[0] == 172 && (m_bytes[1] & 0xF0) == 0x10)
                || (m_bytes[0] == 192 && m_bytes[2] == 168);
        }

        bool operator==(const ipv4_address &rhs) const noexcept = default;
        constexpr auto operator<=>(const ipv4_address &rhs) const noexcept = default;

        template<typename Context>
        friend auto tag_invoke(tag_t<g6::format_to>, ipv4_address const &self, Context &ctx) noexcept {
            return g6::format_to(ctx.out(), "{}.{}.{}.{}",//
                                 self.m_bytes[0], self.m_bytes[1], self.m_bytes[2], self.m_bytes[3]);
        }

        friend std::optional<ipv4_address> tag_invoke(tag_t<g6::from_string<ipv4_address>>,
                                                      std::string_view string) noexcept;

        
        explicit operator uint32_t() noexcept {
            return std::bit_cast<uint32_t>(m_bytes);
        }

    private:
        alignas(std::uint32_t) std::uint8_t m_bytes[4];
    };
}// namespace g6::net
