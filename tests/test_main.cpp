//
// Test runner for StreamAudio project
//

#include "../test_utils.h"
#include <string>

int main(int argc, char* argv[]) {
    // 处理命令行参数
    if (argc > 1)
    {
        std::string arg = argv[1];

        // 帮助信息
        if (arg == "--help" || arg == "-h")
        {
            TestUtils::print_help(argv[0]);
            return 0;
        }

        // 列出所有测试
        if (arg == "--list" || arg == "-l")
        {
            TestUtils::list_tests();
            return 0;
        }

        // 运行匹配的测试
        return TestUtils::run_tests(arg);
    }

    // 运行所有测试
    return TestUtils::run_all_tests();
}
