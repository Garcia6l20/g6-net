g6_add_unit_test(serial-test.cpp)

find_package(Qt6 REQUIRED)

link_libraries(Qt6::Core Qt6::Gui Qt6::Widgets)
if (WIN32)
    link_libraries(Qt6::QWindowsIntegrationPlugin Dwrite)
endif()

add_definitions(-D_ALLOW_COROUTINE_ABI_MISMATCH=1)

g6_add_unit_test(qt-test.cpp)

