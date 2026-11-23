/** @file unitree_live_main.cpp
 *  @brief Accept only the production deployer's read-only attachment invocation.
 */
#include <cstdio>
#include <string_view>

int receive_go2_attachment(char**);

int main(int argc, char** argv) {
    if (argc != 6 || std::string_view(argv[5]) != "read-only") return 2;
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    return receive_go2_attachment(argv);
}
