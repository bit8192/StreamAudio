cmake_minimum_required(VERSION 4.1.2)

# 读取版本配置
file(STRINGS "${CMAKE_SOURCE_DIR}/version.properties" VERSION_PROPS)
foreach(prop ${VERSION_PROPS})
    if(prop MATCHES "^VERSION_NAME=(.*)$")
        set(VERSION_NAME ${CMAKE_MATCH_1})
    elseif(prop MATCHES "^VERSION_CODE=(.*)$")
        set(VERSION_CODE ${CMAKE_MATCH_1})
    endif()
endforeach()

project(StreamSound VERSION ${VERSION_NAME})

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_AUTOMOC ON)

# 生成版本头文件
configure_file(
    "${CMAKE_SOURCE_DIR}/version.h.in"
    "${CMAKE_BINARY_DIR}/version.h"
)
include_directories(${CMAKE_BINARY_DIR})

if (WIN32)
    set(PLATFORM "windows")
    set(STREAM_SOUND_LINK_LIBRARIES ws2_32)
    set(CMAKE_PREFIX_PATH "D:/msys64/mingw64")
elseif (LINUX)
    set(PLATFORM "linux")
    set(STREAM_SOUND_LINK_LIBRARIES pulse pulse-simple)
endif ()

add_executable(StreamSound main.cpp
        platform/${PLATFORM}/audio.cpp
        platform/audio.h
        exceptions.h
        exceptions.cpp
        platform/${PLATFORM}/audio_server.cpp
        platform/audio_server.h
        logger.cpp
        logger.h
        platform/audio_server_common.cpp
        config.cpp
        config.h
        platform/tray_icon.cpp
        platform/tray_icon.h
        platform/qrcode_dialog.cpp
        platform/qrcode_dialog.h
        platform/platform_utils_common.cpp
        platform/platform_utils.h
        tools/crypto.cpp
        tools/crypto.h
        tools/base64.cpp
        tools/base64.h
        tools/string.cpp
        tools/string.h
        tools/qrcodegen.cpp
        tools/qrcodegen.h
        platform/windows/platform_utils.cpp
        data_operator.cpp
        data_operator.h
        data_pack.cpp
        data_pack.h
        protocol_magic.cpp
        protocol_magic.h
        message.cpp
        message.h
        device_config.h
        device.cpp
        device.h
        platform/socket.h
        tools/hextool.cpp
        tools/hextool.h
)

# Debug
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(StreamSound PUBLIC DEBUG_MODE=1)
endif()

# Openssl
find_package(OpenSSL REQUIRED)
list(APPEND STREAM_SOUND_LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)

# yaml-cpp
find_package(yaml-cpp REQUIRED)
list(APPEND STREAM_SOUND_LINK_LIBRARIES yaml-cpp::yaml-cpp)

# Qt
find_package(Qt6 COMPONENTS Core Gui Widgets Network REQUIRED)
list(APPEND STREAM_SOUND_LINK_LIBRARIES Qt::Core Qt::Gui Qt::Widgets Qt::Network)

target_link_libraries(StreamSound ${STREAM_SOUND_LINK_LIBRARIES})

if (WIN32 AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    # ====================================== 拷贝QT依赖
    set(DEBUG_SUFFIX)
    if (MSVC AND CMAKE_BUILD_TYPE MATCHES "Debug")
        set(DEBUG_SUFFIX "d")
    endif ()
    set(QT_INSTALL_PATH "${CMAKE_PREFIX_PATH}")
    if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
        set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        if (NOT EXISTS "${QT_INSTALL_PATH}/bin")
            set(QT_INSTALL_PATH "${QT_INSTALL_PATH}/..")
        endif ()
    endif ()
    if (EXISTS "${QT_INSTALL_PATH}/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
        set(QT_PLUGINS_DIR "${QT_INSTALL_PATH}/plugins")
    elseif (EXISTS "${QT_INSTALL_PATH}/share/qt6/plugins/platforms/qwindows${DEBUG_SUFFIX}.dll")
        set(QT_PLUGINS_DIR "${QT_INSTALL_PATH}/share/qt6/plugins")
    else ()
        message(FATAL_ERROR "NOT FOUND QT PLUGINS DIR")
    endif ()
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms/")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            "${QT_PLUGINS_DIR}/platforms/qwindows${DEBUG_SUFFIX}.dll"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/platforms/")
    foreach (QT_LIB Core)
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${QT_INSTALL_PATH}/bin/Qt6${QT_LIB}${DEBUG_SUFFIX}.dll"
                "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endforeach (QT_LIB)
    # =========================================== 拷贝OpenSSL依赖
    set(OPENSSL_CRYPTO_DLL_FILE "${CMAKE_PREFIX_PATH}/bin/libcrypto-3-x64.dll")
    if (EXISTS "${OPENSSL_CRYPTO_DLL_FILE}")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${OPENSSL_CRYPTO_DLL_FILE}" "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endif ()
    set(OPENSSL_SSL_DLL_FILE "${CMAKE_PREFIX_PATH}/bin/libssl-3-x64.dll")
    if (EXISTS "${OPENSSL_SSL_DLL_FILE}")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${OPENSSL_SSL_DLL_FILE}" "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
    endif ()
endif ()

# 拷贝png图标
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${PROJECT_SOURCE_DIR}/icon.png" "$<TARGET_FILE_DIR:${PROJECT_NAME}>")
