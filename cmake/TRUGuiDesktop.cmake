# GUI-DESKTOP-01: include this from the clean repository root CMakeLists.txt.
# Preserves its source list, options, lineage and production/test targets.
if(BUILD_WITH_QT)
    find_package(Qt5 5.12 REQUIRED COMPONENTS Widgets Network)
    find_path(TRU_QRENCODE_INCLUDE_DIR NAMES qrencode.h)
    find_library(TRU_QRENCODE_LIBRARY NAMES qrencode libqrencode)
    if(NOT TRU_QRENCODE_INCLUDE_DIR OR NOT TRU_QRENCODE_LIBRARY)
        message(FATAL_ERROR "TRU GUI Desktop QR support requires libqrencode")
    endif()
    foreach(_tru_target tru_advanced tru_evolve_token tru_miner tru_miner_cpu tru_wallet blockexplorer)
        if(TARGET ${_tru_target})
            get_target_property(_tru_sources ${_tru_target} SOURCES)
            foreach(_tru_gui_source
                    walletgui.cpp
                    desktop_panel.cpp
                    desktop_rpc.cpp
                    desktop_wallet_core.cpp
                    desktop_wallet_widget.cpp
                    desktop_assets_widget.cpp
                    desktop_ai_widget.cpp)
                set(_tru_present FALSE)
                foreach(_tru_source IN LISTS _tru_sources)
                    get_filename_component(_tru_name "${_tru_source}" NAME)
                    if(_tru_name STREQUAL _tru_gui_source)
                        set(_tru_present TRUE)
                    endif()
                endforeach()
                if(NOT _tru_present)
                    target_sources(${_tru_target} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../src/${_tru_gui_source}")
                endif()
            endforeach()
            target_sources(${_tru_target} PRIVATE
                "${CMAKE_CURRENT_LIST_DIR}/../src/walletgui.h"
                "${CMAKE_CURRENT_LIST_DIR}/../src/desktop_ai_widget.h"
                "${CMAKE_CURRENT_LIST_DIR}/../desktop/assets/tru_desktop.qrc")
            target_compile_definitions(${_tru_target} PRIVATE BUILD_WITH_QT)
            target_include_directories(${_tru_target} PRIVATE "${TRU_QRENCODE_INCLUDE_DIR}")
            target_link_libraries(${_tru_target} PRIVATE
                Qt5::Widgets Qt5::Network "${TRU_QRENCODE_LIBRARY}")
            set_target_properties(${_tru_target} PROPERTIES AUTOMOC ON AUTORCC ON)
        endif()
    endforeach()
endif()
