#include "For_all.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <libaudit.h>
// Реализация getTimestamp()
std::string getTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}
int init_audit_socket() {
    int audit_fd = audit_open();
    if (audit_fd < 0) {
        std::cerr << "❌ Не удалось открыть audit-сокет\n";
        return -1;
    }

    if (audit_set_pid(audit_fd, getpid(), WAIT_YES) <= 0) {
        std::cerr << "❌ Не удалось зарегистрироваться как audit-демон\n";
        close(audit_fd);
        return -1;
    }

    std::cout << "✅ Успешно подключен к audit-сокету\n";
    return audit_fd;
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

