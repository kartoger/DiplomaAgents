#include "For_ScanUsers.h"
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
#include "For_all.h"
// Формирование времени логина в ISO 8601 формате
std::string format_login_time(time_t raw_time) {
    char buf[30];
    std::tm *gmtm = std::gmtime(&raw_time);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtm);
    return std::string(buf);
}

// Получение всех активных пользователей и форматирование логов
void get_active_terminals_logs() {
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

            std::string login_time = format_login_time(entry->ut_tv.tv_sec);

            std::stringstream details;
            details << "Terminal: " << entry->ut_line;

            // Добавляем IP только если терминал начинается с "pts"
            if (line.find("pts") == 0 && std::strlen(entry->ut_host) > 0) {
                details << " IP: " << entry->ut_host;
            }

            details << ", LoginTime: " << login_time;


            // write_log("","","system","Acitve_Terminals",entry->ut_user, details.str() );
            std::cout << LogEntry { .event_name = "system", .event_type = "Active Terminals",.username = entry->ut_user,.details=details.str()};
            logs.push_back(log.str());
        }
    }

    endutent();
    // return logs;
}