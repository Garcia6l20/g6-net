#include <g6/uri.hpp>

#include <ctre.hpp>
#include <utility>

namespace
{
struct impl_t
{
  static constexpr ctll::fixed_string regex =
      R"(^(([^:/?#]+):)?(//(([^/:?#]*))(:([0-9]+))?)?([^?#]*)(\?([^#]*))?(#(.*))?)";
  using builder_type = ctre::regex_builder<regex>;
  static constexpr inline auto match = ctre::regex_match_t<typename builder_type::type>();
} uri_impl;
}  // namespace

namespace g6
{
uri::uri(std::string_view input) noexcept :
    uri_{std::move(input)} {
  if (auto m = uri_impl.match(uri_); m) {
    scheme = m.get<2>();
    host = m.get<5>();
    port = m.get<7>();
    path = m.get<8>();
    parameters = m.get<12>();
  }
}
}  // namespace cppcoro::http
