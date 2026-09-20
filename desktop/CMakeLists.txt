cmake_minimum_required(VERSION 3.16)
project(TRUCoreDesktop LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Qt5 5.12 REQUIRED COMPONENTS Widgets Network)
get_filename_component(TRU_DESKTOP_SRC "${CMAKE_CURRENT_LIST_DIR}/../src" ABSOLUTE)
add_executable(tru_desktop WIN32
    "${TRU_DESKTOP_SRC}/desktop_main.cpp"
    "${TRU_DESKTOP_SRC}/desktop_panel.cpp"
    "${TRU_DESKTOP_SRC}/desktop_rpc.cpp")
target_include_directories(tru_desktop PRIVATE "${TRU_DESKTOP_SRC}")
target_link_libraries(tru_desktop PRIVATE Qt5::Widgets Qt5::Network)
set_target_properties(tru_desktop PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
if(MINGW)
    target_compile_definitions(tru_desktop PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
install(TARGETS tru_desktop RUNTIME DESTINATION bin)
option(TRU_DESKTOP_TESTS "Build offline desktop transport tests" OFF)
if(TRU_DESKTOP_TESTS)
    enable_testing()
    find_package(Qt5 5.12 REQUIRED COMPONENTS Test)
    add_executable(tru_desktop_transport_test
        "${TRU_DESKTOP_SRC}/desktop_rpc_test.cpp"
        "${TRU_DESKTOP_SRC}/desktop_rpc.cpp")
    target_link_libraries(tru_desktop_transport_test PRIVATE Qt5::Network Qt5::Test)
    target_include_directories(tru_desktop_transport_test PRIVATE "${TRU_DESKTOP_SRC}")
    add_test(NAME desktop_transport COMMAND tru_desktop_transport_test)
endif()
