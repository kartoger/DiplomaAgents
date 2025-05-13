#pragma once

#include <string>
#include <ostream>
#include <unistd.h>    // для getlogin()

// Получить текущее время в ISO-формате UTC
std::string getTimestamp();

// Прочитать MAC-адрес из /sys/class/net/... или вернуть 00:...
std::string getMacAddress();
int init_audit_socket();
std::string convertTimestampToISO8601(const std::string& timestampStr);
// Сам LogEntry — только объявление
struct LogEntry {
    std::string timestamp    = getTimestamp();
    std::string mac          = getMacAddress();
    std::string event_name   = "none";
    std::string event_type   = "none";
    std::string username     = getlogin();
    std::string details      = "none";


    // Перегрузка вывода в ostream
    friend std::ostream& operator<<(std::ostream& os, const LogEntry& e);
};

// Декларация write_log с default-параметрами
// (default-аргументы указываем ТОЛЬКО здесь)
void write_log(std::string timestamp   = "",
               std::string mac         = "",
               std::string event_name  = "none",
               std::string event_type  = "none",
               std::string username    = "",
               std::string details     = "none");