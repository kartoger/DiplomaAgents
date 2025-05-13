#include "For_all.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <unistd.h>
// Реализация getTimestamp()
std::string getTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}
std::string convertTimestampToISO8601(const std::string& timestampStr) {
    // Разделяем на секунды и миллисекунды
    size_t dotPos = timestampStr.find('.');

    std::string secondsPart = timestampStr.substr(0, dotPos);
    // Преобразуем строку в целое число
    std::time_t seconds = std::stoll(secondsPart);

    // Преобразуем в UTC
    std::tm* gmtimePtr = std::gmtime(&seconds);

    // Форматируем как ISO 8601
    std::ostringstream oss;
    oss << std::put_time(gmtimePtr, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}
// Реализация getMacAddress()
std::string getMacAddress() {
    std::ifstream file("/sys/class/net/enp3s0/address");
    std::string mac;
    if (file.is_open()) {
        std::getline(file, mac);
    } else {
        mac = "00:00:00:00:00:00";
    }
    return mac;
}


// Перегрузка оператора<< для LogEntry
std::ostream& operator<<(std::ostream& os, const LogEntry& e) {
    return os
        << "[" << e.timestamp    << "] "
        << "[" << e.mac          << "] "
        << "[" << e.event_name
        <<  "::" << e.event_type << "] "
        << "[" << e.username     << "] "
        << "[" << e.details      << "]" << std::endl;
}

// Реализация write_log (без default-аргументов здесь!)
// void write_log(std::string timestamp,
//                std::string mac,
//                std::string event_name,
//                std::string event_type,
//                std::string username,
//                std::string details)
// {
//     if (timestamp.empty())   timestamp = getTimestamp();
//     if (mac.empty())         mac       = getMacAddress();
//     if (username.empty())    username  = getlogin();
//
//     std::cout
//       << "[" << timestamp     << "] "
//       << "[" << mac           << "] "
//       << "[" << event_name
//       <<  "::" << event_type  << "] "
//       << "[" << username      << "] "
//       << "[" << details       << "]\n";
// }