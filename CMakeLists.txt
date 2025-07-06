cmake_minimum_required(VERSION 3.27)
project(StreamSound)

set(CMAKE_CXX_STANDARD 23)

if (WIN32)
    set(PLATFORM "windows")
    set(STREAM_SOUND_LINK_LIBRARIES ws2_32)
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
        tools/crypto.cpp
        tools/crypto.h
        tools/base64.cpp
        tools/base64.h
        tools/string.cpp
        tools/string.h)

find_package(OpenSSL REQUIRED)
list(APPEND STREAM_SOUND_LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)

target_link_libraries(StreamSound ${STREAM_SOUND_LINK_LIBRARIES})
target_link_directories(StreamSound PRIVATE ${OPENSSL_INCLUDE_DIR})
