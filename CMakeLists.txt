cmake_minimum_required(VERSION 3.10)
project(TRUBlockchain)
# TRU Security Patch 01:
# Prefer a local runtime config for native builds when explicitly present.
# Clean clones and Docker builds must not require or consume private tru.conf.
set(TRU_CONFIG_SOURCE "${CMAKE_SOURCE_DIR}/tru.conf")

if(NOT EXISTS "${TRU_CONFIG_SOURCE}")
    if(EXISTS "${CMAKE_SOURCE_DIR}/tru.conf.dockers")
        set(TRU_CONFIG_SOURCE "${CMAKE_SOURCE_DIR}/tru.conf.example")
    elseif(EXISTS "${CMAKE_SOURCE_DIR}/tru.conf.example")
        set(TRU_CONFIG_SOURCE "${CMAKE_SOURCE_DIR}/tru.conf.example")
    else()
        message(FATAL_ERROR
            "No TRU config template found. Expected tru.conf.dockers or tru.conf.example")
    endif()
endif()

message(STATUS "TRU build config source: ${TRU_CONFIG_SOURCE}")
configure_file("${TRU_CONFIG_SOURCE}" "${CMAKE_BINARY_DIR}/bin/tru.conf" COPYONLY)
# Enable AUTOMOC for Qt if needed
set(CMAKE_AUTOMOC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(USE_OPENCL "Use OpenCL for GPU mining" ON)
option(BUILD_WITH_QT "Build with Qt5 support" ON)

# Set sysroot for cross-compilation
if(CMAKE_CROSSCOMPILING)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
        set(CMAKE_SYSROOT /usr/arm-linux-gnueabihf)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        set(CMAKE_SYSROOT /usr/aarch64-linux-gnu)
    endif()
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} --sysroot=${CMAKE_SYSROOT}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --sysroot=${CMAKE_SYSROOT}")
endif()

# Suppress RPATH warnings during cross-compilation
set(CMAKE_SKIP_RPATH TRUE)

# Find dependencies
find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})

find_package(Protobuf REQUIRED)
include_directories(${Protobuf_INCLUDE_DIRS})

# TRU Security Patch 09 v4:
# boost::multiprecision is header-only, but consensus now depends on it.
# Native builds accept Boost >= 1.71; reproducible Docker builds pin 1.83.
find_package(Boost 1.71 REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

if(BUILD_WITH_QT)
    find_package(Qt5 COMPONENTS Widgets REQUIRED)
    add_definitions(-DBUILD_WITH_QT)
endif()

set(OPENSSL_USE_STATIC_LIBS OFF)
find_package(OpenSSL REQUIRED)

find_library(LEVELDB_LIBRARY leveldb REQUIRED
    HINTS ${CMAKE_SYSROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}
)
find_path(LEVELDB_INCLUDE_DIR leveldb/db.h REQUIRED
    HINTS ${CMAKE_SYSROOT}/usr/include
)

find_package(fmt REQUIRED
    HINTS ${CMAKE_SYSROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}/cmake
)

find_package(jsoncpp REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

configure_file(src/allowed_scripts.json ${CMAKE_BINARY_DIR}/bin/allowed_scripts.json COPYONLY)

find_path(ETHASH_INCLUDE_DIR NAMES ethash/ethash.hpp
    HINTS ${CMAKE_SYSROOT}/usr/include
)
find_library(ETHASH_LIBRARY NAMES ethash
    HINTS ${CMAKE_SYSROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}
)

if(NOT ETHASH_INCLUDE_DIR OR NOT ETHASH_LIBRARY)
    message(FATAL_ERROR "Ethash library not found!")
endif()

find_path(CRC32C_INCLUDE_DIR NAMES crc32c/crc32c.h
    HINTS /usr/local/include
)
find_library(CRC32C_LIBRARY NAMES crc32c
    HINTS /usr/local/lib
)
if(NOT CRC32C_LIBRARY)
    message(FATAL_ERROR "crc32c library not found!")
endif()

# OpenCL handling
set(OPENCL_INCLUDE_DIRS "")
set(OPENCL_LIBRARIES "")

if(USE_OPENCL)
    if(NOT WIN32)
        find_package(OpenCL REQUIRED)
        if(OpenCL_FOUND)
            set(OPENCL_INCLUDE_DIRS "${OpenCL_INCLUDE_DIRS}")
            set(OPENCL_LIBRARIES    "${OpenCL_LIBRARIES}")
            message(STATUS "OpenCL found (native): Includes=${OpenCL_INCLUDE_DIRS}, Libs=${OpenCL_LIBRARIES}")
        else()
            message(FATAL_ERROR "OpenCL not found on native build!")
        endif()
    else()
        set(OPENCL_INCLUDE_DIRS "/opt/mxe/usr/x86_64-w64-mingw32.static/include")
        set(OPENCL_LIBRARIES "/opt/mxe/usr/x86_64-w64-mingw32.static/lib/libOpenCL.dll.a")
        if(EXISTS "${OPENCL_INCLUDE_DIRS}/CL/cl.h" AND EXISTS "${OPENCL_LIBRARIES}")
            message(STATUS "Using MXE's OpenCL stub for Windows cross-compile.")
        else()
            message(WARNING "No static OpenCL library found in MXE; proceeding with dynamic load approach.")
            set(OPENCL_INCLUDE_DIRS "")
            set(OPENCL_LIBRARIES "")
        endif()
    endif()
else()
    message(STATUS "USE_OPENCL=OFF => skipping OpenCL detection.")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${LEVELDB_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${ETHASH_INCLUDE_DIR}
    ${OPENCL_INCLUDE_DIRS}
    ${CRC32C_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIRS}
    ${QRENCODE_LIBRARIES}
)

if(NOT CMAKE_CROSSCOMPILING)
    include_directories(/usr/local/include)
endif()

# Common sources and headers
set(COMMON_SOURCES
    src/block.cpp
    src/blockchain.cpp
    src/mempool.cpp
    src/tx.cpp
    src/utxo.cpp
    src/leveldb_storage.cpp
    src/p2p.cpp
    src/crypto_ecdsa.cpp
    src/wallet.cpp
    src/wallet_encryption_v1.cpp
    src/wallet_secret_session_v1.cpp
    src/wallet_security_mode_v1.cpp
    src/wallet_security_controller_v1.cpp
    src/utils.cpp
    src/hdwallet.cpp
    src/kawpow.cpp
    src/peer_connection.cpp
    src/peer_manager.cpp
    src/rpc_server.cpp
    src/message_handler.cpp
    src/message.pb.cc
    src/globals.cpp
    src/stb_image_write.cpp
    src/config_reader.cpp
    src/script_interpreter.cpp
    src/tokens.cpp
    src/logging.cpp
    src/smart_contract.cpp
    src/rpc_utils.cpp
    src/ai_providers.cpp
    src/ai_oracle_service.cpp
    src/vah_capabilities.cpp
    src/vah_authorization.cpp
    src/vah_authorization_store.cpp
    src/vah_external_writer_gate.cpp
    src/vah_external_writer_stage.cpp
    src/vah_external_writer_anchor.cpp
    src/vah_external_writer_anchor_runtime.cpp
    src/vah_external_writer_materialize.cpp
    src/vah_external_writer_materialize_runtime.cpp
    src/vah_sensor_batch.cpp
    src/vah_sensor_batch_accumulator.cpp
    src/vah_sensor_batch_anchor.cpp
    src/vah_sensor_batch_anchor_runtime.cpp
    src/vah_sensor_batch_materialize.cpp
    src/vah_sensor_batch_materialize_runtime.cpp
    src/vah_reconciliation.cpp
    src/vah_observation.cpp
    src/vah_active_chain_observer.cpp
    src/token_evolution.cpp
    src/main_ai_integration.cpp
    src/oobalooga_ai_.h
)

if(USE_OPENCL)
    list(APPEND COMMON_SOURCES src/gpu_miner.cpp)
    add_definitions(-DUSE_OPENCL)
endif()

if(BUILD_WITH_QT)
    list(APPEND COMMON_SOURCES src/walletgui.cpp)
endif()

set(COMMON_HEADERS
    src/block.h
    src/blockchain.h
    src/mempool.h
    src/tx.h
    src/utxo.h
    src/leveldb_storage.h
    src/p2p.h
    src/crypto_ecdsa.h
    src/wallet.h
    src/walletgui.h
    src/utils.h
    src/hdwallet.h
    src/kawpow.h
    src/sha256_21e8.h
    src/gpu_miner.h
    src/peer_connection.h
    src/peer_manager.h
    src/rpc_server.h
    src/stb_image_write.h
    src/wallet_cli.h
    src/address_helpers.h
    src/config_reader.h
    src/opcodes.h
    src/script_interpreter.h
    src/tokens.h
    src/logging.h
    src/main.h
    src/smart_contract.h
    src/rpc_utils.h
    src/contract_storage.h
    src/vah_capabilities.h
    src/vah_authorization.h
    src/vah_authorization_store.h
    src/vah_external_writer_gate.h
    src/vah_external_writer_stage.h
    src/vah_external_writer_anchor.h
    src/vah_external_writer_materialize.h
    src/vah_sensor_batch.h
    src/vah_sensor_batch_accumulator.h
    src/vah_sensor_batch_materialize.h
    src/vah_reconciliation.h
    src/vah_observation.h
    src/master_bridge.h
    src/ai_providers.h
    src/ai_provider_interface.h
    src/ai_oracle_service.h
    src/token_evolution.h
    src/animated_background.h
    src/wallet_styles.h
)

# Executable: Living Token Evolution test CLI (Patch 20)
add_executable(tru_evolve_token
    src/token_evolution_cli.cpp
    ${COMMON_SOURCES}
    ${COMMON_HEADERS}
)

target_link_libraries(tru_evolve_token
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
    ${ETHASH_LIBRARY}
    ${Protobuf_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENCL_LIBRARIES}
    jsoncpp_lib
    ${CRC32C_LIBRARY}
    ${SODIUM_LIBRARIES}
    qrencode
)

if(BUILD_WITH_QT)
    target_link_libraries(tru_evolve_token PRIVATE Qt5::Widgets)
endif()

# Executable: tru_advanced
option(TRU_08B3T_TEST_HOOKS
    "Compile local Patch 08B.3T diagnostic/test hooks into tru_advanced"
    OFF
)

add_executable(tru_advanced
    src/main.cpp
    ${COMMON_SOURCES}
    ${COMMON_HEADERS}
)


# TRU Core v0.06 desktop widget link closure
# DesktopPanel instantiates these widgets only in Qt-enabled Core builds.
if(BUILD_WITH_QT)
    target_sources(tru_advanced PRIVATE
        src/desktop_assets_widget.cpp
        src/desktop_assets_widget.h
        src/desktop_ai_widget.cpp
        src/desktop_ai_widget.h
    )
endif()

if(TRU_08B3T_TEST_HOOKS)
    target_compile_definitions(tru_advanced PRIVATE TRU_08B3T_TEST_HOOKS=1)
    message(STATUS "TRU 08B.3T local test hooks: COMPILED IN (development build)")
else()
    message(STATUS "TRU 08B.3T local test hooks: NOT COMPILED (production default)")
endif()

target_link_libraries(tru_advanced
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
    ${ETHASH_LIBRARY}
    ${Protobuf_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENCL_LIBRARIES}
    jsoncpp_lib
    ${CRC32C_LIBRARY}
    ${SODIUM_LIBRARIES}
    qrencode
)

if(BUILD_WITH_QT)
    target_link_libraries(tru_advanced PRIVATE Qt5::Widgets)
endif()

find_library(WALLY_LIBRARY wallycore
    HINTS ${CMAKE_SYSROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}
)
if(WALLY_LIBRARY)
    target_link_libraries(tru_advanced PRIVATE ${WALLY_LIBRARY})
endif()

find_library(KECCAK_LIBRARY keccak
    HINTS ${CMAKE_SYSROOT}/usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}
)
if(NOT KECCAK_LIBRARY)
    message(FATAL_ERROR "Keccak library not found!")
endif()
target_link_libraries(tru_advanced PRIVATE ${KECCAK_LIBRARY})

# FIX(patch20b): tru_evolve_token is built from COMMON_SOURCES too, so it
# requires the same wallycore + keccak link dependencies as tru_advanced.
if(WALLY_LIBRARY)
    target_link_libraries(tru_evolve_token PRIVATE ${WALLY_LIBRARY})
endif()
target_link_libraries(tru_evolve_token PRIVATE ${KECCAK_LIBRARY})

set_target_properties(tru_evolve_token PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(tru_advanced PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Executable: tru_miner
add_executable(tru_miner
    src/my_gpu_miner.cpp
    ${COMMON_SOURCES}
    ${COMMON_HEADERS}
)

target_link_libraries(tru_miner
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
    ${ETHASH_LIBRARY}
    ${Protobuf_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENCL_LIBRARIES}
    jsoncpp_lib
    ${CRC32C_LIBRARY}
    ${SODIUM_LIBRARIES}
    qrencode
)

if(BUILD_WITH_QT)
    target_link_libraries(tru_miner PRIVATE Qt5::Widgets)
endif()
if(WALLY_LIBRARY)
    target_link_libraries(tru_miner PRIVATE ${WALLY_LIBRARY})
endif()
target_link_libraries(tru_miner PRIVATE ${KECCAK_LIBRARY})

set_target_properties(tru_miner PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Executable: tru_miner_cpu (Static Linking)
add_executable(tru_miner_cpu
    src/my_miner.cpp
    ${COMMON_SOURCES}
    ${COMMON_HEADERS}
)

target_link_libraries(tru_miner_cpu
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
    ${ETHASH_LIBRARY}
    ${Protobuf_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENCL_LIBRARIES}
    jsoncpp_lib
    ${CRC32C_LIBRARY}
    ${SODIUM_LIBRARIES}
    qrencode
)

if(BUILD_WITH_QT)
    target_link_libraries(tru_miner_cpu PRIVATE Qt5::Widgets)
endif()
if(WALLY_LIBRARY)
    target_link_libraries(tru_miner_cpu PRIVATE ${WALLY_LIBRARY})
endif()
target_link_libraries(tru_miner_cpu PRIVATE ${KECCAK_LIBRARY})

set_target_properties(tru_miner_cpu PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LINK_FLAGS "-static-libgcc -static-libstdc++"
)

# Executable: tru_wallet (Static Linking)
add_executable(tru_wallet
    src/wallet_cli.cpp
    ${COMMON_SOURCES}
    ${COMMON_HEADERS}
)

target_link_libraries(tru_wallet
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
    ${ETHASH_LIBRARY}
    ${Protobuf_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENCL_LIBRARIES}
    jsoncpp_lib
    ${CRC32C_LIBRARY}
    ${SODIUM_LIBRARIES}
    qrencode
)

if(BUILD_WITH_QT)
    target_link_libraries(tru_wallet PRIVATE Qt5::Widgets)
endif()
if(WALLY_LIBRARY)
    target_link_libraries(tru_wallet PRIVATE ${WALLY_LIBRARY})
endif()
target_link_libraries(tru_wallet PRIVATE ${KECCAK_LIBRARY})

set_target_properties(tru_wallet PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LINK_FLAGS "-static-libgcc -static-libstdc++"
)

# Executable: blockexplorer (Static Linking)
add_executable(blockexplorer
    src/explorer_main.cpp
    src/blockexplorer.cpp
    src/utils.h
    ${COMMON_SOURCES}
    ${COMMON_HEADERS}
)

target_link_libraries(blockexplorer
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
    ${ETHASH_LIBRARY}
    ${Protobuf_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENCL_LIBRARIES}
    ${KECCAK_LIBRARY}
    jsoncpp_lib
    ${CRC32C_LIBRARY}
    ${SODIUM_LIBRARIES}
    qrencode
)

if(BUILD_WITH_QT)
    target_link_libraries(blockexplorer PRIVATE Qt5::Widgets)
endif()
if(WALLY_LIBRARY)
    target_link_libraries(blockexplorer PRIVATE ${WALLY_LIBRARY})
endif()

set_target_properties(blockexplorer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LINK_FLAGS "-static-libgcc -static-libstdc++"
)

# Debug and warning options
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(tru_advanced   PRIVATE -g -O0)
    target_compile_options(tru_miner      PRIVATE -g -O0)
    target_compile_options(tru_miner_cpu  PRIVATE -g -O0)
    target_compile_options(tru_wallet     PRIVATE -g -O0)
    target_compile_options(blockexplorer  PRIVATE -g -O0)
endif()

target_compile_options(tru_advanced   PRIVATE -Wno-deprecated-declarations)
target_compile_options(tru_miner      PRIVATE -Wno-deprecated-declarations)
target_compile_options(tru_miner_cpu  PRIVATE -Wno-deprecated-declarations)
target_compile_options(tru_wallet     PRIVATE -Wno-deprecated-declarations)
target_compile_options(blockexplorer  PRIVATE -Wno-deprecated-declarations)

# ============================================================================
#  tru-cli  --  standalone JSON-RPC client (pure client; no node sources)
# ============================================================================
add_executable(tru-cli
    src/tru-cli.cpp
)

target_link_libraries(tru-cli
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    pthread
)

target_compile_options(tru-cli PRIVATE -Wno-deprecated-declarations)

set_target_properties(tru-cli PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LINK_FLAGS "-static-libgcc -static-libstdc++"
)

# Status messages
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Ethash includes: ${ETHASH_INCLUDE_DIR}")
message(STATUS "Ethash library: ${ETHASH_LIBRARY}")
message(STATUS "USE_OPENCL = ${USE_OPENCL}")
if(USE_OPENCL AND OPENCL_LIBRARIES)
    message(STATUS "Final OpenCL libs: ${OPENCL_LIBRARIES}")
endif()


# ============================================================================
# TRU AI Provenance V1 closeout DEV-only fault-injection target.
# This target is not a dependency of tru_advanced and its test macro is scoped
# to this executable only. Production binaries cannot enable these hooks.
# ============================================================================
add_executable(tru_ai_provenance_closeout_dev EXCLUDE_FROM_ALL
    src/token_evolution_closeout_test.cpp
    src/token_evolution.cpp
    src/vah_capabilities.cpp
    src/leveldb_storage.cpp
    src/logging.cpp
)
target_compile_definitions(tru_ai_provenance_closeout_dev PRIVATE
    TRU_TOKEN_EVOLUTION_TEST_FAULTS=1
)
target_link_libraries(tru_ai_provenance_closeout_dev PRIVATE
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
)
target_compile_options(tru_ai_provenance_closeout_dev PRIVATE -Wno-deprecated-declarations)
set_target_properties(tru_ai_provenance_closeout_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)


# ============================================================================
# VAH-01ABC DEV-only typed capability matrix.  No chain/storage access.
# ============================================================================
add_executable(tru_vah_01_capabilities_dev EXCLUDE_FROM_ALL
    src/vah_capabilities_test.cpp
    src/vah_capabilities.cpp
)
target_compile_options(tru_vah_01_capabilities_dev PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(tru_vah_01_capabilities_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)


# ============================================================================
# VAH-01D/E DEV-only signed authorization + historical verifier matrix.
# No chain/storage access and no external writer activation.
# ============================================================================
add_executable(tru_vah_01_authorization_dev EXCLUDE_FROM_ALL
    src/vah_authorization_test.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/crypto_ecdsa.cpp
    src/logging.cpp
)
target_link_libraries(tru_vah_01_authorization_dev PRIVATE
    OpenSSL::Crypto
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_01_authorization_dev PRIVATE -Wno-deprecated-declarations -Wall -Wextra -Wpedantic)
set_target_properties(tru_vah_01_authorization_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)


# ============================================================================
# VAH-01F DEV-only durable authorization persistence / crash-retry matrix.
# Uses isolated /tmp LevelDBs only; never production chain state.
# ============================================================================
add_executable(tru_vah_01_persistence_dev EXCLUDE_FROM_ALL
    src/vah_authorization_store_test.cpp
    src/vah_authorization_store.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/leveldb_storage.cpp
    src/crypto_ecdsa.cpp
    src/logging.cpp
)
target_compile_definitions(tru_vah_01_persistence_dev PRIVATE
    TRU_VAH_AUTH_STORE_TEST_FAULTS=1
    TRU_TOKEN_EVOLUTION_TEST_FAULTS=1
)
target_link_libraries(tru_vah_01_persistence_dev PRIVATE
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_01_persistence_dev PRIVATE -Wno-deprecated-declarations -Wall -Wextra -Wpedantic)
set_target_properties(tru_vah_01_persistence_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)


# ============================================================
# VAH-02A — deterministic canonical epoch election DEV target
# EXCLUDE_FROM_ALL: no production runtime activation.
# ============================================================
add_executable(tru_vah_02_reconciliation_dev EXCLUDE_FROM_ALL
    src/vah_reconciliation_test.cpp
    src/vah_reconciliation.cpp
)
target_include_directories(tru_vah_02_reconciliation_dev PRIVATE src)
target_compile_options(tru_vah_02_reconciliation_dev PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(tru_vah_02_reconciliation_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)


# ============================================================
# VAH-02B — bounded candidate transport + confirmed active-chain
# observation DEV target.  No P2P acceptance or storage mutation.
# ============================================================
add_executable(tru_vah_02_observation_dev EXCLUDE_FROM_ALL
    src/vah_observation_test.cpp
    src/vah_observation.cpp
    src/vah_reconciliation.cpp
)
target_include_directories(tru_vah_02_observation_dev PRIVATE src)
target_compile_options(tru_vah_02_observation_dev PRIVATE -Wall -Wextra -Wpedantic)
set_target_properties(tru_vah_02_observation_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================
# VAH-02C — durable reconciliation + restart proof DEV target.
# EXCLUDE_FROM_ALL: persistence/restart proof only; no production runtime
# caller or P2P path is activated by this target.
# ============================================================
add_executable(tru_vah_02_durable_reconciliation_dev EXCLUDE_FROM_ALL
    src/vah_reconciliation_store_test.cpp
    src/vah_reconciliation_store.cpp
    src/vah_reconciliation.cpp
    src/leveldb_storage.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_02_durable_reconciliation_dev PRIVATE src)
target_link_libraries(tru_vah_02_durable_reconciliation_dev PRIVATE
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_02_durable_reconciliation_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_02_durable_reconciliation_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)


# ============================================================
# VAH-02D — strong record binding + reconciliation closure DEV target.
# TRU_EVOLVE_V2 is defined/observed here but no production writer, P2P
# acceptance, TOKEN_EVOLUTION mutation, or external-writer activation occurs.
# ============================================================
add_executable(tru_vah_02_record_binding_dev EXCLUDE_FROM_ALL
    src/vah_record_binding_test.cpp
    src/vah_observation.cpp
    src/vah_reconciliation.cpp
    src/vah_reconciliation_store.cpp
    src/leveldb_storage.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_02_record_binding_dev PRIVATE src)
target_link_libraries(tru_vah_02_record_binding_dev PRIVATE
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_02_record_binding_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_02_record_binding_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================
# VAH-03A — controlled external-writer activation gate.
# The verifier is compiled into production, but there is intentionally no
# RPC/P2P/runtime caller yet and no persistence/TOKEN_EVOLUTION mutation path.
# ============================================================
add_executable(tru_vah_03_external_writer_gate_dev EXCLUDE_FROM_ALL
    src/vah_external_writer_gate_test.cpp
    src/vah_external_writer_gate.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/crypto_ecdsa.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_03_external_writer_gate_dev PRIVATE src)
target_link_libraries(tru_vah_03_external_writer_gate_dev PRIVATE
    OpenSSL::Crypto
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_03_external_writer_gate_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_03_external_writer_gate_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================
# VAH-03B — bounded local claim intake + durable staging.
# Production compiles the staging primitive, but no RPC/P2P/runtime ingress,
# TRU_EVOLVE_V2 emission, or TOKEN_EVOLUTION mutation caller is enabled here.
# ============================================================
add_executable(tru_vah_03_external_writer_stage_dev EXCLUDE_FROM_ALL
    src/vah_external_writer_stage_test.cpp
    src/vah_external_writer_stage.cpp
    src/vah_external_writer_gate.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/leveldb_storage.cpp
    src/crypto_ecdsa.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_03_external_writer_stage_dev PRIVATE src)
target_link_libraries(tru_vah_03_external_writer_stage_dev PRIVATE
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_03_external_writer_stage_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_03_external_writer_stage_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)



# ============================================================
# VAH-03C — production V2 anchor emission + confirmed-chain admission.
# The runtime primitive is compiled into production and can broadcast only an
# already-funded/signed transaction for an exact VAH-03B staged claim. No RPC
# or P2P writer ingress and no TOKEN_EVOLUTION materialization is enabled.
# ============================================================
add_executable(tru_vah_03_external_writer_anchor_dev EXCLUDE_FROM_ALL
    src/vah_external_writer_anchor_test.cpp
    src/vah_external_writer_anchor.cpp
    src/vah_external_writer_gate.cpp
    src/vah_observation.cpp
    src/vah_reconciliation.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/crypto_ecdsa.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_03_external_writer_anchor_dev PRIVATE src)
target_link_libraries(tru_vah_03_external_writer_anchor_dev PRIVATE
    OpenSSL::Crypto
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_03_external_writer_anchor_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_03_external_writer_anchor_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================
# VAH-03D — canonical external-writer materialization closeout.
# DEV target uses isolated /tmp LevelDB and test-only winner/fault hooks.
# Production compiles only the confirm->materialize internal primitive; there
# is still no RPC/P2P writer ingress, automatic worker, or chain reset path.
# ============================================================
add_executable(tru_vah_03_external_writer_materialize_dev EXCLUDE_FROM_ALL
    src/vah_external_writer_materialize_test.cpp
    src/vah_external_writer_materialize.cpp
    src/vah_external_writer_stage.cpp
    src/vah_external_writer_gate.cpp
    src/vah_reconciliation.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/token_evolution.cpp
    src/leveldb_storage.cpp
    src/crypto_ecdsa.cpp
    src/logging.cpp
)
target_compile_definitions(tru_vah_03_external_writer_materialize_dev PRIVATE
    TRU_VAH_03D_TEST_HOOKS=1
    TRU_TOKEN_EVOLUTION_TEST_FAULTS=1
)
target_include_directories(tru_vah_03_external_writer_materialize_dev PRIVATE src)
target_link_libraries(tru_vah_03_external_writer_materialize_dev PRIVATE
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_03_external_writer_materialize_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_03_external_writer_materialize_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================
# VAH-04A — canonical sensor-batch envelope + Merkle commitments.
# Pure bounded cryptographic foundation only: no durable batch accumulator,
# RPC/P2P ingress, anchor emission, or TOKEN_EVOLUTION mutation is enabled.
# ============================================================
add_executable(tru_vah_04_sensor_batch_dev EXCLUDE_FROM_ALL
    src/vah_sensor_batch_test.cpp
    src/vah_sensor_batch.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/crypto_ecdsa.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_04_sensor_batch_dev PRIVATE src)
target_link_libraries(tru_vah_04_sensor_batch_dev PRIVATE
    OpenSSL::Crypto
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_04_sensor_batch_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_04_sensor_batch_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================
# VAH-04B — restart-safe local sensor-feed accumulator.
# Durable batch/head continuity only: no RPC/P2P ingress, sensor-batch anchor
# emission, TOKEN_EVOLUTION mutation, wallet spending, or chain reset.
# ============================================================
add_executable(tru_vah_04_sensor_batch_accumulator_dev EXCLUDE_FROM_ALL
    src/vah_sensor_batch_accumulator_test.cpp
    src/vah_sensor_batch_accumulator.cpp
    src/vah_sensor_batch.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/crypto_ecdsa.cpp
    src/leveldb_storage.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_04_sensor_batch_accumulator_dev PRIVATE src)
target_link_libraries(tru_vah_04_sensor_batch_accumulator_dev PRIVATE
    OpenSSL::Crypto
    ${LEVELDB_LIBRARY}
    fmt::fmt
    pthread
)
target_compile_options(tru_vah_04_sensor_batch_accumulator_dev PRIVATE
    -Wno-deprecated-declarations -Wall -Wextra -Wpedantic
)
set_target_properties(tru_vah_04_sensor_batch_accumulator_dev PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# ============================================================
# VAH-04C — authorized sensor-batch anchor + active-chain confirmation.
# Internal production primitive only; no RPC/P2P ingress, automatic worker,
# TOKEN_EVOLUTION mutation, wallet spending, or chain-policy change.
# ============================================================
add_executable(tru_vah_04_sensor_batch_anchor_dev EXCLUDE_FROM_ALL
    src/vah_sensor_batch_anchor_test.cpp
    src/vah_sensor_batch_anchor.cpp
    src/leveldb_storage.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_04_sensor_batch_anchor_dev PRIVATE src)
target_link_libraries(tru_vah_04_sensor_batch_anchor_dev PRIVATE OpenSSL::Crypto ${LEVELDB_LIBRARY} fmt::fmt pthread)
target_compile_options(tru_vah_04_sensor_batch_anchor_dev PRIVATE -Wno-deprecated-declarations -Wall -Wextra -Wpedantic)
set_target_properties(tru_vah_04_sensor_batch_anchor_dev PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(tru_vah_04_sensor_batch_materialize_dev EXCLUDE_FROM_ALL
    src/vah_sensor_batch_materialize_test.cpp
    src/vah_sensor_batch_materialize.cpp
    src/vah_sensor_batch_anchor.cpp
    src/vah_sensor_batch_accumulator.cpp
    src/vah_sensor_batch.cpp
    src/vah_authorization.cpp
    src/vah_capabilities.cpp
    src/crypto_ecdsa.cpp
    src/leveldb_storage.cpp
    src/logging.cpp
)
target_include_directories(tru_vah_04_sensor_batch_materialize_dev PRIVATE src)
target_link_libraries(tru_vah_04_sensor_batch_materialize_dev PRIVATE OpenSSL::Crypto ${LEVELDB_LIBRARY} fmt::fmt pthread)
target_compile_options(tru_vah_04_sensor_batch_materialize_dev PRIVATE -Wno-deprecated-declarations -Wall -Wextra -Wpedantic)
set_target_properties(tru_vah_04_sensor_batch_materialize_dev PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# GUI-DESKTOP-01 clean repository GUI integration
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/TRUGuiDesktop.cmake")
