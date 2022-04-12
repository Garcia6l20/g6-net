find_package(Qt6 REQUIRED)

link_libraries(Qt6::Qt6)
if (WIN32)
    link_libraries(Qt6::QWindowsIntegrationPlugin Dwrite)
    add_definitions(-D_ALLOW_COROUTINE_ABI_MISMATCH=1)
else()
    find_package(md4c REQUIRED)
    link_libraries(md4c::md4c xcb-xinput)
endif()

g6_add_unit_test(qt-test.cpp)
