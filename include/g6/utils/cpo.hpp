#pragma once

#include <g6/tag_invoke.hpp>
#include <utility>


namespace g6::_generic_cpo {
    template<typename Concrete>
    struct generic_cpo {
        template<typename... Args>
        auto operator()(Args &&...args) const noexcept(g6::nothrow_tag_invocable_c<Concrete, Args...>) {
            return g6::tag_invoke(*static_cast<Concrete *>(this), std::forward<Args>(args)...);
        }
    };
}// namespace g6::_generic_cpo

#define G6_CPO_DEF(__name)                                                                                             \
    namespace __name##_cpo_ {                                                                                          \
        inline const struct fn_ : g6::_generic_cpo::generic_cpo<fn_> { } __name{}; }                                   \
    using __name##_cpo_::__name;
