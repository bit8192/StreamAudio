cmake_minimum_required(VERSION 3.27)
project(StreamSound)

set(CMAKE_CXX_STANDARD 23)
if (WIN32)
    set(STREAM_SOUND_LINK_LIBRARIES ws2_32)
    set(PLATFORM "windows")
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
        platform/audio_server.h)

target_link_libraries(StreamSound ${STREAM_SOUND_LINK_LIBRARIES})
