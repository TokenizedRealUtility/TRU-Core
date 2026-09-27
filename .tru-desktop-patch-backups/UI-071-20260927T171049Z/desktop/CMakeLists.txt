cmake_minimum_required(VERSION 3.16)
project(TRUCoreDesktop LANGUAGES CXX)
if(APPLE)
    cmake_minimum_required(VERSION 3.21.1)
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(TRU_DESKTOP_QT_MAJOR "5" CACHE STRING "Desktop Qt major version (5 or 6)")
set_property(CACHE TRU_DESKTOP_QT_MAJOR PROPERTY STRINGS 5 6)
if(TRU_DESKTOP_QT_MAJOR STREQUAL "6")
    find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets Network)
elseif(TRU_DESKTOP_QT_MAJOR STREQUAL "5")
    find_package(Qt5 5.12 REQUIRED COMPONENTS Widgets Network)
else()
    message(FATAL_ERROR "TRU_DESKTOP_QT_MAJOR must be 5 or 6")
endif()
set(_tru_qt "Qt${TRU_DESKTOP_QT_MAJOR}")

# DESKTOP-WALLET-01 crypto/storage dependencies.
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_path(TRU_SODIUM_INCLUDE_DIR NAMES sodium.h)
find_library(TRU_SODIUM_LIBRARY NAMES sodium libsodium)
find_path(TRU_WALLY_INCLUDE_DIR NAMES wally_bip32.h)
find_library(TRU_WALLY_LIBRARY NAMES wallycore wally)
find_path(TRU_QRENCODE_INCLUDE_DIR NAMES qrencode.h)
find_library(TRU_QRENCODE_LIBRARY NAMES qrencode libqrencode)

if(NOT TRU_SODIUM_INCLUDE_DIR OR NOT TRU_SODIUM_LIBRARY)
    message(FATAL_ERROR "DESKTOP-WALLET-01 requires libsodium headers/library")
endif()
if(NOT TRU_WALLY_INCLUDE_DIR OR NOT TRU_WALLY_LIBRARY)
    message(FATAL_ERROR "DESKTOP-WALLET-01 requires libwally-core headers/library")
endif()
if(NOT TRU_QRENCODE_INCLUDE_DIR OR NOT TRU_QRENCODE_LIBRARY)
    message(FATAL_ERROR "TRU Desktop QR support requires libqrencode headers/library")
endif()
get_filename_component(TRU_DESKTOP_SRC "${CMAKE_CURRENT_LIST_DIR}/../src" ABSOLUTE)
add_executable(tru_desktop WIN32
    "${TRU_DESKTOP_SRC}/desktop_main.cpp"
    "${TRU_DESKTOP_SRC}/desktop_panel.cpp"
    "${TRU_DESKTOP_SRC}/desktop_rpc.cpp"
    "${TRU_DESKTOP_SRC}/desktop_wallet_core.cpp"
    "${TRU_DESKTOP_SRC}/desktop_wallet_widget.cpp"
    "${TRU_DESKTOP_SRC}/desktop_assets_widget.cpp"
    "${TRU_DESKTOP_SRC}/desktop_ai_widget.cpp"
    "${TRU_DESKTOP_SRC}/wallet_encryption_v1.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/assets/tru_desktop.qrc")
target_include_directories(tru_desktop PRIVATE
    "${TRU_DESKTOP_SRC}"
    "${TRU_SODIUM_INCLUDE_DIR}"
    "${TRU_WALLY_INCLUDE_DIR}"
    "${TRU_QRENCODE_INCLUDE_DIR}")
target_link_libraries(tru_desktop PRIVATE
    ${_tru_qt}::Widgets
    ${_tru_qt}::Network
    OpenSSL::Crypto
    "${TRU_SODIUM_LIBRARY}"
    "${TRU_WALLY_LIBRARY}"
    "${TRU_QRENCODE_LIBRARY}")
set_target_properties(tru_desktop PROPERTIES
    AUTOMOC ON
    AUTORCC ON
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
if(MINGW)
    target_compile_definitions(tru_desktop PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()
if(APPLE)
    set(TRU_DESKTOP_BUNDLE_ID "com.tokenizedrealutility.desktop" CACHE STRING "macOS desktop bundle identifier")
    # Packaging metadata follows the repository VERSION file.
    # This affects only the macOS application bundle; it does not alter
    # blockchain consensus, validation, P2P, wallet, or RPC behavior.
    set(_tru_version_file "${CMAKE_CURRENT_LIST_DIR}/../VERSION")
    if(NOT EXISTS "${_tru_version_file}")
        message(FATAL_ERROR "TRU VERSION file not found: ${_tru_version_file}")
    endif()
    file(STRINGS "${_tru_version_file}" TRU_DESKTOP_REPO_VERSION LIMIT_COUNT 1)
    string(STRIP "${TRU_DESKTOP_REPO_VERSION}" TRU_DESKTOP_REPO_VERSION)
    if(NOT TRU_DESKTOP_REPO_VERSION MATCHES "^[0-9]+\.[0-9]+\.[0-9]+$")
        message(FATAL_ERROR "Invalid TRU VERSION for macOS bundle: ${TRU_DESKTOP_REPO_VERSION}")
    endif()
    set(TRU_DESKTOP_APP_VERSION "${TRU_DESKTOP_REPO_VERSION}"
        CACHE STRING "macOS desktop package version")
    set_target_properties(tru_desktop PROPERTIES
        MACOSX_BUNDLE TRUE
        OUTPUT_NAME "TRU Core Desktop"
        MACOSX_BUNDLE_BUNDLE_NAME "TRU Core Desktop"
        MACOSX_BUNDLE_GUI_IDENTIFIER "${TRU_DESKTOP_BUNDLE_ID}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${TRU_DESKTOP_APP_VERSION}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${TRU_DESKTOP_APP_VERSION}"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_LIST_DIR}/macos/Info.plist.in")
endif()
install(TARGETS tru_desktop BUNDLE DESTINATION . RUNTIME DESTINATION bin)
option(TRU_DESKTOP_TESTS "Build offline desktop transport tests" OFF)
if(TRU_DESKTOP_TESTS)
    enable_testing()
    find_package(${_tru_qt} REQUIRED COMPONENTS Test)
    add_executable(tru_desktop_transport_test
        "${TRU_DESKTOP_SRC}/desktop_rpc_test.cpp"
        "${TRU_DESKTOP_SRC}/desktop_rpc.cpp")
    target_link_libraries(tru_desktop_transport_test PRIVATE ${_tru_qt}::Network ${_tru_qt}::Test)
    target_include_directories(tru_desktop_transport_test PRIVATE "${TRU_DESKTOP_SRC}")
    add_test(NAME desktop_transport COMMAND tru_desktop_transport_test)

    add_executable(tru_desktop_wallet_test
        "${TRU_DESKTOP_SRC}/desktop_wallet_test.cpp"
        "${TRU_DESKTOP_SRC}/desktop_wallet_core.cpp"
        "${TRU_DESKTOP_SRC}/wallet_encryption_v1.cpp")
    target_include_directories(tru_desktop_wallet_test PRIVATE
        "${TRU_DESKTOP_SRC}"
        "${TRU_SODIUM_INCLUDE_DIR}"
        "${TRU_WALLY_INCLUDE_DIR}")
    target_link_libraries(tru_desktop_wallet_test PRIVATE
        OpenSSL::Crypto
        "${TRU_SODIUM_LIBRARY}"
        "${TRU_WALLY_LIBRARY}")
    add_test(NAME desktop_wallet COMMAND tru_desktop_wallet_test)
endif()
