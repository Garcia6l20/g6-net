#pragma once

#include <unifex/tag_invoke.hpp>

namespace g6::_generic_cpo {
    template<typename Concrete>
    struct generic_cpo {
        template<typename... Args>
        auto operator()(Args &&...args) const noexcept(unifex::is_nothrow_tag_invocable_v<Concrete, Args...>)
            -> unifex::tag_invoke_result_t<Concrete, Args...> {
            return unifex::tag_invoke(*static_cast<Concrete const *>(this), std::forward<Args>(args)...);
        }
    };
}// namespace g6::_generic_cpo

#define G6_CPO_DEF(__name)                                                                                             \
    namespace __name##_cpo_ {                                                                                          \
        inline const struct fn_ : g6::_generic_cpo::generic_cpo<fn_> { } __name{}; }                                   \
    using __name##_cpo_::__name;
