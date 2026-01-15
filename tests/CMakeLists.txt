# Test executable configuration
cmake_minimum_required(VERSION 3.22)

# 如果独立运行此文件，需要设置项目
if(NOT CMAKE_PROJECT_NAME)
    project(StreamAudioTests)
    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)

# 创建测试可执行文件
add_executable(run_tests
        ../platform/${CMAKE_SYSTEM_NAME}/audio.cpp
        ../platform/audio.h
        ../exceptions.h
        ../exceptions.cpp
        ../platform/${CMAKE_SYSTEM_NAME}/audio_server.cpp
        ../platform/audio_server.h
        ../logger.cpp
        ../logger.h
        ../platform/audio_server_common.cpp
        ../config.cpp
        ../config.h
        ../tray_icon.cpp
        ../tray_icon.h
        ../qrcode_dialog.cpp
        ../qrcode_dialog.h
        ../platform_utils.cpp
        ../platform_utils.h
        ../tools/crypto.cpp
        ../tools/crypto.h
        ../tools/base64.cpp
        ../tools/base64.h
        ../tools/string.cpp
        ../tools/string.h
        ../tools/qrcodegen.cpp
        ../tools/qrcodegen.h
        ../protocol_magic.cpp
        ../protocol_magic.h
        ../message.cpp
        ../message.h
        ../device_config.h
        ../device.cpp
        ../device.h
        ../platform/socket.h
        ../tools/hextool.cpp
        ../tools/hextool.h
#        //======================= Test Files =================//
        test_main.cpp
        crypto_test.cpp
        ware_test.cpp
        cpp_test.cpp
)


if (WIN32)
    set(TEST_LINK_LIBRARIES ws2_32)
#    set(CMAKE_PREFIX_PATH "D:/msys64/mingw64")
elseif (LINUX)
    set(TEST_LINK_LIBRARIES pulse pulse-simple)
endif ()

# Openssl
#find_package(OpenSSL REQUIRED)
list(APPEND TEST_LINK_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)

# yaml-cpp
#find_package(yaml-cpp REQUIRED)
list(APPEND TEST_LINK_LIBRARIES yaml-cpp::yaml-cpp)

# Qt
#find_package(Qt6 COMPONENTS Core Gui Widgets Network REQUIRED)
list(APPEND TEST_LINK_LIBRARIES Qt::Core Qt::Gui Qt::Widgets Qt::Network)

target_link_libraries(run_tests PRIVATE ${TEST_LINK_LIBRARIES})

# 添加测试目标
add_custom_target(test
    COMMAND run_tests
    DEPENDS run_tests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/tests
    COMMENT "Running tests..."
)
