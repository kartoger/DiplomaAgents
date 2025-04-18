#include <iostream>
#include <string>
#include <regex>
#include <cstdio>

int main() {
    // Открываем поток journalctl на чтение
    FILE* pipe = popen("journalctl -f --no-pager | grep --line-buffered -E 'sshd|gdm-password'", "r");
    if (!pipe) {
        std::cerr << "Ошибка при запуске journalctl!" << std::endl;
        return 1;
    }

    char buffer[2048];
    std::regex sshRegex(R"(sshd.*Failed password for (?:invalid user )?(\S+) from (\S+))");
    std::regex gdmRegex(R"(gdm-password.*authentication failure.*user=(\S+))");

    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);

        std::smatch match;

        // Проверка на ssh ошибку входа
        if (std::regex_search(line, match, sshRegex)) {
            std::string username = match[1];
            std::string ip = match[2];

            std::cout << line.substr(0, 15) << " sshd: Failed password for " << username
                      << " from " << ip << std::endl;
        }

        // Проверка на gdm ошибку входа
        else if (std::regex_search(line, match, gdmRegex)) {
            std::string username = match[1];

            std::cout << line.substr(0, 15) << " gdm-password: authentication failure for "
                      << username << std::endl;
        }
    }

    pclose(pipe);
    return 0;
}
