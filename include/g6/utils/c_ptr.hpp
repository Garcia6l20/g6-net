/** @file g6/utils/c_ptr.hpp
 * @author Sylvain Garcia <garcia.6l20@gmail.com>
 */
#pragma once

#include <memory>

namespace g6 {

	template <typename T>
	void no_free_func(T *) {}

	/** @brief C-struct deleter.
	 * 
	 * @tparam T            The C-struct.
	 * @tparam free_func    The free function to apply before delete.
	 */
    template <typename T, auto free_func>
    struct c_deleter {
        void operator()(T *ptr) noexcept {
            free_func(ptr);
            delete ptr;
        }
    };

	/** @brief C-struct shared pointer.
	 *
	 * @tparam T            The C-struct.
	 * @tparam init_func    The init function.
	 * @tparam free_func    The free function.
	 */
	template <typename T, auto init_func, auto free_func = no_free_func<T>>
	struct c_shared_ptr : std::shared_ptr<T> {

        c_shared_ptr(c_shared_ptr&& other) = default;
        c_shared_ptr(const c_shared_ptr& other) = default;
		virtual ~c_shared_ptr() = default;

		template <typename...ArgsT>
        explicit c_shared_ptr(T *ptr, ArgsT...args) noexcept : std::shared_ptr<T>{ptr, c_deleter<T, free_func>{}} {
			init_func(ptr, std::forward<ArgsT>(args)...);
		}

        template <typename...ArgsT>
        static auto make(ArgsT &&...args) noexcept {
            return c_shared_ptr{new T, std::forward<ArgsT>(args)...};
        }
	};

    /** @brief C-struct unique pointer.
     *
     * @tparam T            The C-struct.
     * @tparam init_func    The init function.
     * @tparam free_func    The free function.
     */
    template <typename T, auto init_func, auto free_func = no_free_func<T>>
    struct c_unique_ptr : std::unique_ptr<T, c_deleter<T, free_func>> {
        using std::unique_ptr<T, c_deleter<T, free_func>>::operator=;

        template <typename...ArgsT>
        explicit c_unique_ptr(T *ptr, ArgsT...args) noexcept : std::unique_ptr<T, c_deleter<T, free_func>>{ptr} {
            init_func(ptr, std::forward<ArgsT>(args)...);
        }

        template <typename...ArgsT>
        static auto make(ArgsT &&...args) noexcept {
            return c_unique_ptr{new T, std::forward<ArgsT>(args)...};
        }
    };
}
