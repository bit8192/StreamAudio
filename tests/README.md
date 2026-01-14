# StreamAudio 测试指南

本项目使用一个轻量级的自定义测试框架，无需外部依赖（如 Google Test）即可编写和运行测试。

## 目录结构

```
StreamAudio/
├── test_utils.h          # 测试工具库（断言宏、测试注册等）
└── tests/
    ├── CMakeLists.txt    # 测试构建配置
    ├── test_main.cpp     # 测试入口
    └── crypto_test.cpp   # 加密模块测试示例
```

## 构建和运行测试

### 启用测试构建

```bash
# 配置 CMake 并启用测试
cmake -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON

# 构建测试可执行文件
cmake --build cmake-build-debug --target run_tests

# 运行测试
./cmake-build-debug/tests/run_tests
```

### 快速运行

```bash
# 一行命令构建并运行
cmake --build cmake-build-debug --target run_tests && ./cmake-build-debug/tests/run_tests
```

## 编写测试

### 基本测试结构

使用 `TEST()` 宏定义测试用例，测试会自动注册：

```cpp
#include "../test_utils.h"
#include "../your_module.h"

TEST(test_name) {
    // 测试代码
    int result = add(2, 3);
    ASSERT_EQ(result, 5);
}
```

### 可用的断言宏

#### 布尔断言
```cpp
ASSERT_TRUE(condition);   // 断言条件为真
ASSERT_FALSE(condition);  // 断言条件为假
```

#### 相等性断言
```cpp
ASSERT_EQ(actual, expected);  // 断言相等
ASSERT_NE(actual, expected);  // 断言不相等
```

#### 异常断言
```cpp
ASSERT_THROW(statement, ExceptionType);  // 断言抛出指定异常
ASSERT_NO_THROW(statement);              // 断言不抛出异常
```

### 完整示例

```cpp
#include "../test_utils.h"
#include "../tools/crypto.h"

// 测试 SHA256 哈希
TEST(sha256_basic) {
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    auto hash = Crypto::sha256(data);

    ASSERT_EQ(hash.size(), 32);

    std::string expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    ASSERT_EQ(TestUtils::to_hex(hash), expected);
}

// 测试异常处理
TEST(invalid_input) {
    std::vector<uint8_t> empty_key;
    std::vector<uint8_t> data = {'t', 'e', 's', 't'};

    ASSERT_THROW(
        Crypto::aes_256_gcm_encrypt(empty_key, data, data),
        CryptoException
    );
}

// 测试边界情况
TEST(empty_data) {
    std::vector<uint8_t> empty;
    auto result = process_data(empty);

    ASSERT_TRUE(result.empty());
    ASSERT_EQ(result.size(), 0);
}
```

## 辅助工具函数

测试工具库提供了一些实用函数：

```cpp
// 字节数组比较
bool bytes_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// 字节数组转十六进制字符串
std::string to_hex(const std::vector<uint8_t>& data);

// 十六进制字符串转字节数组
std::vector<uint8_t> from_hex(const std::string& hex);
```

使用示例：

```cpp
TEST(hex_conversion) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::string hex = TestUtils::to_hex(data);

    ASSERT_EQ(hex, "48656c6c6f");

    auto decoded = TestUtils::from_hex(hex);
    ASSERT_TRUE(TestUtils::bytes_equal(data, decoded));
}
```

## 添加新的测试文件

1. 在 `tests/` 目录下创建新的测试文件，例如 `my_module_test.cpp`

2. 在文件中包含测试工具和被测试模块：
   ```cpp
   #include "../test_utils.h"
   #include "../my_module.h"

   TEST(my_first_test) {
       // 测试代码
   }

   TEST(my_second_test) {
       // 测试代码
   }
   ```

3. 在 `tests/test_main.cpp` 中包含新的测试文件：
   ```cpp
   #include "../test_utils.h"
   #include "crypto_test.cpp"
   #include "my_module_test.cpp"  // 添加这行

   int main(int argc, char* argv[]) {
       return TestUtils::run_all_tests();
   }
   ```

4. 重新构建并运行测试

## 测试输出

测试运行时会显示彩色输出（支持 ANSI 终端）：

```
═══════════════════════════════════════
  Running 12 test(s)
═══════════════════════════════════════

Running: sha256_basic
  ✓ PASSED

Running: aes_gcm_wrong_key
  ✓ PASSED

Running: invalid_test
  ✗ FAILED: Assertion failed: result == 42
    Expected: 42
    Actual:   0
    at test.cpp:15

═══════════════════════════════════════
Test Results:
  Total:  12
  Passed: 11
  Failed: 1
═══════════════════════════════════════
```

## 最佳实践

### 1. 测试命名

使用描述性的测试名称：

```cpp
TEST(sha256_basic)                    // ✓ 清晰
TEST(test1)                           // ✗ 不明确
TEST(aes_gcm_wrong_key)              // ✓ 描述测试场景
TEST(encryption_error)                // ✗ 过于笼统
```

### 2. 每个测试一个关注点

```cpp
// ✓ 好的做法
TEST(encrypt_basic) {
    auto encrypted = encrypt(data, key);
    ASSERT_EQ(encrypted.size(), expected_size);
}

TEST(decrypt_basic) {
    auto decrypted = decrypt(encrypted, key);
    ASSERT_EQ(decrypted, original_data);
}

// ✗ 避免在一个测试中测试太多东西
TEST(crypto_everything) {
    // 测试加密、解密、签名、验证...
}
```

### 3. 测试边界情况

```cpp
TEST(empty_input)         // 空输入
TEST(large_input)         // 大数据
TEST(invalid_input)       // 无效输入
TEST(null_pointer)        // 空指针
TEST(buffer_overflow)     // 缓冲区溢出
```

### 4. 使用辅助函数提高可读性

```cpp
// 创建测试数据的辅助函数
std::vector<uint8_t> create_test_key() {
    return Crypto::sha256(std::vector<uint8_t>{'k', 'e', 'y'});
}

TEST(encryption_with_helper) {
    auto key = create_test_key();
    auto result = encrypt(data, key);
    ASSERT_TRUE(result.size() > 0);
}
```

## 与 CI/CD 集成

测试可执行文件返回状态码：
- `0`: 所有测试通过
- `1`: 至少一个测试失败

在 CI 脚本中使用：

```bash
#!/bin/bash
cmake -B build -DBUILD_TESTS=ON
cmake --build build --target run_tests
./build/tests/run_tests
if [ $? -ne 0 ]; then
    echo "Tests failed!"
    exit 1
fi
```

## 常见问题

### Q: 如何跳过某些测试？

A: 在测试函数开头添加 `return`：

```cpp
TEST(experimental_feature) {
    return;  // 暂时跳过这个测试
    // 测试代码...
}
```

### Q: 如何运行单个测试？

A: 目前需要注释掉其他测试的包含或修改代码。未来可以添加命令行参数支持。

### Q: 测试失败时如何获取更多信息？

A: 断言宏会自动打印失败位置和值。可以在测试中添加 `std::cout` 输出调试信息：

```cpp
TEST(debug_test) {
    auto result = complex_calculation();
    std::cout << "Result: " << result << std::endl;
    ASSERT_EQ(result, expected);
}
```

## 参考示例

查看 `tests/crypto_test.cpp` 获取完整的测试示例，包括：

- 基本功能测试
- 异常处理测试
- 边界条件测试
- 与其他平台（Kotlin）的兼容性测试
- 密钥交换和签名验证测试

## 总结

这个轻量级测试框架提供了：

- ✓ 零外部依赖
- ✓ 简单的 API（TEST 宏 + ASSERT 宏）
- ✓ 自动测试注册
- ✓ 彩色输出
- ✓ 详细的失败信息
- ✓ CI/CD 友好

适合中小型项目快速编写和运行单元测试！
