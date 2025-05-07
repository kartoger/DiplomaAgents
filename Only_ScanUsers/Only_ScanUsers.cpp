#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <cstring>
#include <utmp.h>


// Получение текущего времени в ISO 8601 формате
std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm *gmtm = std::gmtime(&now_time);
    char buf[30];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtm);
    return std::string(buf);
}

// Формирование времени логина в ISO 8601 формате
std::string format_login_time(time_t raw_time) {
    char buf[30];
    std::tm *gmtm = std::gmtime(&raw_time);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtm);
    return std::string(buf);
}

// Получение MAC-адреса указанного интерфейса через файловую систему
std::string get_mac_address(const std::string& interface) {
    std::ifstream file("/sys/class/net/" + interface + "/address");
    if (!file.is_open()) return "none";
    std::string mac;
    std::getline(file, mac);
    return mac;
}

// Получение всех активных пользователей и форматирование логов
std::vector<std::string> get_active_user_logs(const std::string &mac_address) {
    std::vector<std::string> logs;

    setutent();
    struct utmp *entry;

    while ((entry = getutent()) != nullptr) {
        if (entry->ut_type == USER_PROCESS) {
            std::string line(entry->ut_line);

            // Пропустить seat0
            if (line == "seat0") {
                continue;
            }

            std::stringstream log;
            std::string timestamp = get_current_timestamp();
            std::string login_time = format_login_time(entry->ut_tv.tv_sec);

            std::stringstream details;
            details << "[Terminal: " << entry->ut_line;

            // Добавляем IP только если терминал начинается с "pts"
            if (line.find("pts") == 0 && std::strlen(entry->ut_host) > 0) {
                details << " IP: " << entry->ut_host;
            }

            details << ", LoginTime: " << login_time << "]";

            log << "[" << timestamp << "]"
                << "[" << mac_address << "]"
                << "[system::active_users]"
                << "[" << entry->ut_user << "]"
                << "[" << details.str() << "]";

            logs.push_back(log.str());
        }
    }

    endutent();
    return logs;
}

int main() {
    std::string interface_name = "enp3s0"; // или поменяй на свой интерфейс: "wlan0"
    std::string mac_address = get_mac_address(interface_name);

    std::vector<std::string> logs = get_active_user_logs(mac_address);

    for (const auto &log : logs) {
        std::cout << log << std::endl;
    }

    return 0;
}
