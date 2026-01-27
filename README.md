# StreamAudio (C++ Server)

![icon](./icon.svg)  
跨平台音频流服务器，支持 Windows 与 Linux。  
Android客户端： [https://github.com/bit8192/StreamAudioAndroid](https://github.com/bit8192/StreamAudioAndroid)  

## 使用方法
- 下载解压/安装
- 双击打开主应用程序(StreamAudio)
- 右键任务栏图标
- 点击移动客户端，并使用Android手机扫描二维码进行安装（已安装则跳过）
- 点击配对二维码
- 打开Android客户端，点击右上角扫描二维码
- 在客户端中点击播放

> 客户端与服务端需在同一局域网中  
> Android客户端播放后若熄屏同时没有音频播放一段时间后会被系统强制冻结，建议对该应用设置关闭电源优化

## 依赖
- Qt6
- OpenSSL
- yaml-cpp
- Linux：PulseAudio
- Windows：Winsock2

## 构建
```bash
# Debug 构建
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug
```

## 运行
```bash
./cmake-build-debug/StreamAudio
```

## 测试
```bash
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
cmake --build cmake-build-debug --target run_tests
./cmake-build-debug/tests/run_tests
```

## 目录结构简述
- `main.cpp` 与根目录 `*.cpp/*.h`：核心逻辑与入口
- `platform/`：平台相关实现（Windows/Linux）
- `tools/`：通用工具（加密、Base64、字符串、二维码等）
- `tests/`：自定义测试框架与测试用例

## 配置与密钥
- Windows：`%USERPROFILE%\.config\stream-sound\`
- Linux：`~/.config/stream-sound/`

## 开源协议
GPL-3.0，详见 `LICENSE`。
