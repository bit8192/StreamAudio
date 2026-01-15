# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

StreamAudio 是一个跨平台的音频流服务器项目，用于捕获系统音频并通过网络传输给客户端。该项目使用 C++23 编写，支持 Windows 和 Linux 平台。

**协议架构** (重构中):
- **TCP**: 用于客户端认证、控制消息和密钥交换
- **UDP**: 用于音频流传输（纯音频数据，使用 TCP 协商的 AES-256 密钥加密）

## 构建系统

### 构建命令

```bash
# Debug 构建
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug

# Release 构建
cmake -B cmake-build-release -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-release

# 运行
./cmake-build-debug/StreamAudio    # Debug 版本
./cmake-build-release/StreamAudio  # Release 版本
```

### 平台依赖

- **Windows**: 需要 ws2_32 (Winsock2)，使用 WASAPI 进行音频捕获
- **Linux**: 需要 PulseAudio (`pulse`, `pulse-simple`)
- **通用**: 需要 OpenSSL (用于加密功能)

CMake 通过 `WIN32` 和 `LINUX` 变量自动选择平台特定的源文件和链接库。

## 架构设计

### 核心模块

#### 1. 音频捕获层 (`platform/audio.h`, `platform/{windows,linux}/audio.cpp`)

跨平台音频捕获抽象，提供统一的 `Audio` 类接口：

- **Windows 实现**: 使用 WASAPI (Windows Audio Session API) 捕获系统音频输出（扬声器回路）
  - 基于 COM 接口：`IMMDeviceEnumerator`, `IAudioClient`, `IAudioCaptureClient`
  - 使用 loopback 模式捕获系统播放的所有音频

- **Linux 实现**: 使用 PulseAudio Simple API
  - 使用 `pa_simple` 接口进行音频流捕获

- **统一接口**:
  - `get_audio_info()`: 获取音频格式（采样率、位深度、声道数等）
  - `capture(callback)`: 通过回调函数持续提供音频数据块

#### 2. 网络服务层 (`platform/audio_server.h`, `platform/**/audio_server.cpp`)

**AudioServer** 类负责网络通信和客户端管理：

- **平台特定部分** (`platform/windows/audio_server.cpp`, `platform/linux/audio_server.cpp`):
  - Socket 库初始化/清理（Windows 需要 WSAStartup/WSACleanup）
  - 平台特定的网络 API 调用

- **平台无关部分** (`platform/audio_server_common.cpp`):
  - 客户端连接管理和认证逻辑
  - 加密/解密功能实现
  - 配对流程处理
  - 密钥管理（加载/保存已认证客户端）

#### 3. 加密系统 (`tools/crypto.h`, `tools/crypto.cpp`)

基于 OpenSSL 的加密功能封装：

- **X25519 类**: ECDH 密钥交换
  - `generate()`: 生成新密钥对
  - `derive_shared_secret()`: 使用对方公钥派生共享密钥（支持盐值）

- **ED25519 类**: 数字签名和身份验证
  - `generate()`: 生成新签名密钥对
  - `sign()`: 对数据签名
  - `verify()`: 验证签名
  - 支持 PEM 格式的密钥导入/导出

- **辅助函数**:
  - `hmac_sha256()`: HMAC-SHA256 消息认证
  - `sha256()`: SHA-256 哈希

**加密流程** (`audio_server_common.cpp`):
- `encrypt()`: AES-256-CBC 加密，返回 `[IV(16字节)][密文][padding]`
- `decrypt()`: AES-256-CBC 解密

#### 4. 数据操作器 (`data_operator.h`, `data_operator.cpp`)

**DataOperator** 类：类似 Java ByteBuffer 的二进制数据序列化/反序列化工具

核心功能：
- 读写基本类型：`get()/put()`, `get_uint16()/put_uint16()`, `get_int()/put_int()`
- 数组操作：`get_array()`, `put_array()`, `copy_to()`
- 字节序控制：`set_order(ORDER_BIG_ENDIAN | ORDER_LITTLE_ENDIAN)`
- 缓冲区管理：`mark()`, `reset()`, `flip()`, `clear()`
- 调试工具：`to_hex()` - 转换为十六进制字符串

**使用模式**：
```cpp
DataOperator op(buffer, size);
op.put_uint16(value);
op.put_array(data);
// 解析时
uint16_t val = op.get_uint16();
auto arr = op.get_array(len);
```

### 客户端配对和认证流程

#### 配对流程（用于新客户端）

1. **密钥交换**: 客户端和服务器进行 ECDH (X25519) 密钥交换，派生会话密钥
2. **配对码验证**:
   - 用户在服务器控制台运行 `pair <code> <name>` 命令
   - 客户端在有效时间内发送匹配的配对码
3. **身份保存**: 配对成功后，客户端的 ED25519 公钥保存到配置文件
4. **后续连接**: 已配对客户端使用 ED25519 签名进行身份验证

#### 配置文件位置

- **Windows**: `%USERPROFILE%\.config\stream-sound\`
- **Linux**: `~/.config/stream-sound/`

关键文件：
- `sign-key.pem`: 服务器的 ED25519 私钥（自动生成）
- `.authenticated`: 已认证客户端列表
  - 格式: `<算法> <base64公钥> <客户端名称>`
  - 示例: `ed25519 aBcD...123= MyPhone`

### 数据结构

#### audio_info
音频格式信息（`platform/audio.h:41-46`）：
```cpp
struct audio_info {
    uint32_t sample_rate;  // 采样率（如 48000）
    uint16_t bits;         // 位深度（如 16）
    uint16_t format;       // 格式代码
    uint16_t channels;     // 声道数（1=单声道, 2=立体声）
};
```

#### client_info
客户端连接状态（`platform/audio_server.h:61-68`）：
- `address`: 客户端 socket 地址
- `active_time`: 最后活跃时间（用于超时检测）
- `ecdh_pub_key`: 客户端的 X25519 公钥
- `session_key`: 派生的会话密钥（用于 AES 加密）
- `key`: 指向已保存的 ED25519 身份密钥（已认证客户端）
- `play`: 是否正在播放音频

## 工具模块

### Base64 (`tools/base64.h`)
用于配置文件中公钥的编码/解码

### String (`tools/string.h`)
字符串处理工具，主要是 `split()` 函数用于解析命令和配置行

### Logger (`logger.h`)
简单的日志系统，支持五个级别：
```cpp
Logger::t(tag, message);  // trace
Logger::d(tag, message);  // debug
Logger::i(tag, message);  // info
Logger::w(tag, message);  // warn
Logger::e(tag, message);  // error
Logger::e(tag, message, exception);  // error with exception
```

## 命令行交互

服务器启动后支持以下命令：
- `pair <code> <name>` - 启动配对流程，等待客户端输入匹配的配对码并保存为指定名称
- `quit` - 退出服务器

## 平台特定开发注意事项

### Windows
- 需要初始化 COM (`CoInitialize`) 用于 WASAPI
- 需要初始化 Winsock (`WSAStartup`)
- 音频捕获使用 loopback 模式的 `IMMDevice`
- 使用 `%USERPROFILE%` 环境变量定位用户目录

### Linux
- 使用 PulseAudio 的简单同步 API (`pa_simple`)
- 使用 POSIX socket API
- 使用 `$HOME` 环境变量定位用户目录

### 跨平台兼容
- `HOME_DIR` 常量在 `audio_server.h:16,21` 根据平台自动设置
- Socket 类型和函数通过条件编译适配
- 使用 `std::filesystem::path` 处理路径拼接（注意最近修复了 Windows 路径拼接 BUG）

## 相关子项目

- **StreamAudioAndroid/**: Android 客户端（独立的 Gradle 项目，不在主 CMake 构建中）

## 当前开发状态

根据 git 日志，项目正在进行数据包结构的重构设计。所有主要源文件都有未提交的修改。
