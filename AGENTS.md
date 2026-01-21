# Repository Guidelines

## 项目结构与模块组织
- `main.cpp` 与根目录的 `*.cpp/*.h` 为核心逻辑与入口。
- `platform/` 存放平台相关实现（`Windows/`、`Linux/`），包含音频捕获与网络服务适配。
- `tools/` 提供加密、Base64、字符串、二维码等通用工具。
- `tests/` 为自定义测试框架与测试用例，测试入口在 `tests/test_main.cpp`。
- `StreamAudioAndroid/` 为独立的 Android 客户端工程，不参与主 CMake 构建。

## 构建、测试与开发命令
```bash
# Debug 构建
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug

# 运行服务器
./cmake-build-debug/StreamAudio

# 启用并构建测试
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build cmake-build-debug --target run_tests
./cmake-build-debug/tests/run_tests
```
- 依赖：Qt6、OpenSSL、yaml-cpp；Linux 需 PulseAudio；Windows 使用 Winsock2。
- 在 WSL 环境建议使用 `cmake-build-wsl` 作为构建目录。

## 编码风格与命名约定
- 语言标准：C++23；缩进 4 空格，`{` 与控制语句同一行。
- 类型/类使用 `PascalCase`（如 `AudioServer`），函数使用 `lower_snake_case`（如 `get_audio_info`）。
- 常量与宏使用大写（如 `LOG_TAG`）。
- 新增平台代码应放入 `platform/<SystemName>/` 并通过 CMake 条件编译接入。

## 测试指南
- 使用自定义测试框架（`test_utils.h`），通过 `TEST(name)` 注册用例。
- 新增测试文件后需在 `tests/test_main.cpp` 中 include。
- 命名建议：体现场景与预期结果，例如 `aes_gcm_wrong_key`。

## 提交与 PR 指南
- 历史提交以中文简短描述为主，建议采用“动词 + 对象/结果”的一行消息。
- PR 需说明改动范围、关联问题/需求、关键命令运行结果；涉及 UI（托盘/二维码）请附截图。

## 配置与密钥
- 配置与密钥默认存放于用户目录：Windows `%USERPROFILE%\.config\stream-sound\`，Linux `~/.config/stream-sound/`。
- 涉及密钥与认证逻辑的改动请附带测试用例或验证步骤。
