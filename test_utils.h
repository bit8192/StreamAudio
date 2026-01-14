//
// Simple testing utility for projects without test frameworks
// Created for StreamAudio project
//

#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <iostream>
#include <functional>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

namespace TestUtils
{
    // 测试统计信息
    struct TestStats
    {
        int total = 0;
        int passed = 0;
        int failed = 0;
    };

    // 全局测试统计
    inline TestStats& get_stats()
    {
        static TestStats stats;
        return stats;
    }

    // 当前测试名称
    inline std::string& current_test_name()
    {
        static std::string name;
        return name;
    }

    // 测试失败时的颜色输出
    inline const char* RED = "\033[31m";
    inline const char* GREEN = "\033[32m";
    inline const char* YELLOW = "\033[33m";
    inline const char* RESET = "\033[0m";

    // 断言宏
#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            std::cerr << TestUtils::RED << "  ✗ ASSERTION FAILED: " << #condition \
                      << "\n    at " << __FILE__ << ":" << __LINE__ << TestUtils::RESET << std::endl; \
            throw std::runtime_error("Assertion failed: " #condition); \
        } \
    } while(0)

#define ASSERT_FALSE(condition) ASSERT_TRUE(!(condition))

#define ASSERT_EQ(actual, expected) \
    do { \
        if ((actual) != (expected)) { \
            std::cerr << TestUtils::RED << "  ✗ ASSERTION FAILED: " << #actual << " == " << #expected \
                      << "\n    Expected: " << (expected) \
                      << "\n    Actual:   " << (actual) \
                      << "\n    at " << __FILE__ << ":" << __LINE__ << TestUtils::RESET << std::endl; \
            throw std::runtime_error("Assertion failed"); \
        } \
    } while(0)

#define ASSERT_NE(actual, expected) \
    do { \
        if ((actual) == (expected)) { \
            std::cerr << TestUtils::RED << "  ✗ ASSERTION FAILED: " << #actual << " != " << #expected \
                      << "\n    at " << __FILE__ << ":" << __LINE__ << TestUtils::RESET << std::endl; \
            throw std::runtime_error("Assertion failed"); \
        } \
    } while(0)

#define ASSERT_THROW(statement, exception_type) \
    do { \
        bool caught = false; \
        try { \
            statement; \
        } catch (const exception_type&) { \
            caught = true; \
        } catch (...) { \
            std::cerr << TestUtils::RED << "  ✗ ASSERTION FAILED: " << #statement \
                      << " threw wrong exception type\n    Expected: " << #exception_type \
                      << "\n    at " << __FILE__ << ":" << __LINE__ << TestUtils::RESET << std::endl; \
            throw; \
        } \
        if (!caught) { \
            std::cerr << TestUtils::RED << "  ✗ ASSERTION FAILED: " << #statement \
                      << " did not throw " << #exception_type \
                      << "\n    at " << __FILE__ << ":" << __LINE__ << TestUtils::RESET << std::endl; \
            throw std::runtime_error("Expected exception not thrown"); \
        } \
    } while(0)

#define ASSERT_NO_THROW(statement) \
    do { \
        try { \
            statement; \
        } catch (const std::exception& e) { \
            std::cerr << TestUtils::RED << "  ✗ ASSERTION FAILED: " << #statement \
                      << " threw exception: " << e.what() \
                      << "\n    at " << __FILE__ << ":" << __LINE__ << TestUtils::RESET << std::endl; \
            throw; \
        } \
    } while(0)

    // 辅助函数：比较字节数组
    inline bool bytes_equal(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
    {
        return a == b;
    }

    // 辅助函数：将字节数组转换为十六进制字符串
    inline std::string to_hex(const std::vector<uint8_t>& data)
    {
        std::ostringstream oss;
        for (auto byte : data)
        {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }

    // 辅助函数：从十六进制字符串转换为字节数组
    inline std::vector<uint8_t> from_hex(const std::string& hex)
    {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byte_str = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    // 测试用例结构
    struct TestCase
    {
        std::string name;
        std::function<void()> func;
    };

    // 测试注册表
    inline std::vector<TestCase>& get_test_registry()
    {
        static std::vector<TestCase> registry;
        return registry;
    }

    // 注册测试
    inline void register_test(const std::string& name, std::function<void()> func)
    {
        get_test_registry().push_back({name, func});
    }

    // 运行单个测试
    inline bool run_test(const TestCase& test)
    {
        current_test_name() = test.name;
        auto& stats = get_stats();
        stats.total++;

        std::cout << "Running: " << test.name << std::endl;

        try
        {
            test.func();
            std::cout << GREEN << "  ✓ PASSED" << RESET << std::endl;
            stats.passed++;
            return true;
        }
        catch (const std::exception& e)
        {
            std::cerr << RED << "  ✗ FAILED: " << e.what() << RESET << std::endl;
            stats.failed++;
            return false;
        }
        catch (...)
        {
            std::cerr << RED << "  ✗ FAILED: Unknown exception" << RESET << std::endl;
            stats.failed++;
            return false;
        }
    }

    // 列出所有可用的测试
    inline void list_tests()
    {
        auto& registry = get_test_registry();
        std::cout << "Available tests:" << std::endl;
        for (const auto& test : registry)
        {
            std::cout << "  - " << test.name << std::endl;
        }
    }

    // 运行匹配模式的测试
    inline int run_tests(const std::string& pattern = "")
    {
        auto& registry = get_test_registry();
        auto& stats = get_stats();

        // 过滤测试
        std::vector<TestCase> tests_to_run;
        if (pattern.empty())
        {
            tests_to_run = registry;
        }
        else
        {
            for (const auto& test : registry)
            {
                if (test.name.find(pattern) != std::string::npos)
                {
                    tests_to_run.push_back(test);
                }
            }
        }

        if (tests_to_run.empty())
        {
            std::cerr << RED << "No tests match pattern: '" << pattern << "'" << RESET << std::endl;
            return 1;
        }

        std::cout << "\n" << YELLOW << "═══════════════════════════════════════" << RESET << std::endl;
        if (pattern.empty())
        {
            std::cout << YELLOW << "  Running " << tests_to_run.size() << " test(s)" << RESET << std::endl;
        }
        else
        {
            std::cout << YELLOW << "  Running " << tests_to_run.size() << " test(s) matching '"
                      << pattern << "'" << RESET << std::endl;
        }
        std::cout << YELLOW << "═══════════════════════════════════════" << RESET << "\n" << std::endl;

        for (const auto& test : tests_to_run)
        {
            run_test(test);
            std::cout << std::endl;
        }

        // 打印统计信息
        std::cout << YELLOW << "═══════════════════════════════════════" << RESET << std::endl;
        std::cout << "Test Results:" << std::endl;
        std::cout << "  Total:  " << stats.total << std::endl;
        std::cout << GREEN << "  Passed: " << stats.passed << RESET << std::endl;
        if (stats.failed > 0)
        {
            std::cout << RED << "  Failed: " << stats.failed << RESET << std::endl;
        }
        else
        {
            std::cout << "  Failed: " << stats.failed << std::endl;
        }
        std::cout << YELLOW << "═══════════════════════════════════════" << RESET << std::endl;

        return stats.failed == 0 ? 0 : 1;
    }

    // 向后兼容的函数
    inline int run_all_tests()
    {
        return run_tests("");
    }

    // 打印帮助信息
    inline void print_help(const char* program_name)
    {
        std::cout << "Usage: " << program_name << " [OPTIONS] [PATTERN]\n\n";
        std::cout << "Options:\n";
        std::cout << "  --help, -h       Show this help message\n";
        std::cout << "  --list, -l       List all available tests\n";
        std::cout << "  PATTERN          Run only tests matching PATTERN\n\n";
        std::cout << "Examples:\n";
        std::cout << "  " << program_name << "                    # Run all tests\n";
        std::cout << "  " << program_name << " aes              # Run tests with 'aes' in name\n";
        std::cout << "  " << program_name << " aes_gcm_basic    # Run specific test\n";
        std::cout << "  " << program_name << " --list           # List all tests\n";
    }
} // namespace TestUtils

// 便捷宏：定义测试
#define TEST(test_name) \
    void test_##test_name(); \
    namespace { \
        struct TestRegistrar_##test_name { \
            std::string name = #test_name;\
            TestRegistrar_##test_name() { \
                TestUtils::register_test(#test_name, test_##test_name); \
            } \
        }; \
        static TestRegistrar_##test_name registrar_##test_name; \
    } \
    void test_##test_name()

#endif // TEST_UTILS_H
