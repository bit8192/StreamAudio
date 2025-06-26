cmake_minimum_required(VERSION 3.27)
project(StreamSound)

set(CMAKE_CXX_STANDARD 23)

add_executable(StreamSound main.cpp
        platform/windows/audio.cpp
        platform/audio.h
        exceptions.h
        exceptions.cpp
        platform/windows/audio_server.cpp
        platform/audio_server.h)

if (WIN32)
    target_link_libraries(StreamSound ws2_32)
elseif (LINUX)
    target_link_libraries(StreamSound pulseaudio libpulse)
endif ()
