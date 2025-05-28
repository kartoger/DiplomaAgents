#include "For_all.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libaudit.h>
#include <pwd.h>
#include <regex>
#include <sstream>
#include <unistd.h>
#include <unordered_map>
//1234

// ThreadSafeQueue<AuditMessage> audit_event_queue;
ThreadSafeQueue<AuditMessage> queue_mount;
ThreadSafeQueue<AuditMessage> queue_exec;



void audit_event_reader(int audit_fd) {
    struct audit_reply rep{};
    std::cout << "[audit_event_reader] started\n";
    while (true) {
        memset(&rep, 0, sizeof(rep));
        int rc = audit_get_reply(audit_fd, &rep, GET_REPLY_BLOCKING, 0);

        if (rc <= 0 || !rep.message) {
            std::cerr << "⚠️ Ошибка чтения audit: " << rc << "\n";
            continue;
        }

        AuditMessage msg{
            .type = rep.type,
            .message = rep.message ? std::string(rep.message) : ""
        };
        // std::cout << "|" <<  rep.message << std::endl;

        // AuditMessage msg{.type = rep.type, .message = rep.message};
        queue_mount.push(msg);
        queue_exec.push(msg);
    }
}

void debug_audit_reader(int audit_fd) {
    struct audit_reply rep{};
    while (true) {
        memset(&rep, 0, sizeof(rep));
        int rc = audit_get_reply(audit_fd, &rep, GET_REPLY_BLOCKING, 0);
        if (rc > 0 && rep.message) {
            std::cout << "[AUDIT RAW] " << rep.message << std::endl;
        }
    }
}
int extract_ppid(const std::string& msg) {
    static const std::regex ppid_regex(R"(ppid=(\d+))");
    std::smatch match;
    if (std::regex_search(msg, match, ppid_regex) && match.size() > 1) {
        try {
            return std::stoi(match[1]);
        } catch (...) {}
    }
    return -1;
}
std::string extract_cwd_path(const std::string& msg) {
    static const std::regex cwd_regex(R"(cwd=\"([^\"]+)\")");
    std::smatch match;
    if (std::regex_search(msg, match, cwd_regex)) {
        return match[1];
    }
    return "";
}
int extract_pid(const std::string& msg) {
    static const std::regex pid_regex(R"(pid=(\d+))");
    std::smatch match;
    if (std::regex_search(msg, match, pid_regex) && match.size() > 1) {
        try {
            return std::stoi(match[1]);
        } catch (...) {}
    }
    return -1;
}
void handleCwdPath(const std::string& msg, std::unordered_map<int, std::string>& pidToUnmountPath) {
    static const std::regex cwd_regex(R"(cwd=\"([^\"]+)\")");
    std::smatch match;

    if (std::regex_search(msg, match, cwd_regex) && match.size() > 1) {
        std::string cwd = match[1];
        int pid = extract_pid(msg);
        if (!cwd.empty() && pid != -1) {
            pidToUnmountPath[pid] = cwd;
        }

    }
}

std::string extract_syscall_comm(const std::string& msg) {
    static const std::regex regex(R"(comm=\"([^\"]+)\")");
    std::smatch match;
    if (std::regex_search(msg, match, regex)) {
        return match[1];
    }
    return "";
}
std::string extract_syscall_num(const std::string& msg) {
    static const std::regex regex(R"(syscall=(\d+))");

    std::smatch match;
    if (std::regex_search(msg, match, regex)) {
        return match[1];
    }
    return "";
}
std::string extract_syscall_exe(const std::string& msg) {
    static const std::regex regex(R"(exe=\"([^\"]+)\")");
    std::smatch match;
    if (std::regex_search(msg, match, regex)) {
        return match[1];
    }
    return "";
}
std::string extract_path_path(const std::string& msg) {
    static const std::regex regex(R"(name=\"([^\"]+)\")");
    std::smatch match;
    if (std::regex_search(msg, match, regex)) {
        return match[1];
    }
    return "";
}

std::string extract_syscall_username(const std::string& msg) {
    static const std::regex uid_regex(R"(uid=(\d+))");
    static const std::regex euid_regex(R"(euid=(\d+))");
    static const std::regex auid_regex(R"(auid=(\d+))");

    std::smatch match_uid, match_auid, match_euid;

    uid_t uid = -1;
    uid_t auid = -1;
    uid_t euid = -1;

    try {
        if (std::regex_search(msg, match_auid, auid_regex) && match_auid.size() > 1)
            auid = static_cast<uid_t>(std::stoul(match_auid[1]));
        if (std::regex_search(msg, match_uid, uid_regex) && match_uid.size() > 1)
            uid = static_cast<uid_t>(std::stoul(match_uid[1]));
        if (std::regex_search(msg, match_euid, euid_regex) && match_euid.size() > 1)
            euid = static_cast<uid_t>(std::stoul(match_euid[1]));
    } catch (const std::exception& e) {
        std::cerr << "Ошибка парсинга UID: " << e.what() << "\n";
        std::cerr << "[debug] msg: " << msg << "\n";
        return "unknown";
    }

    // 4294967295 или -1 — означает "нет пользователя"
    if (auid == static_cast<uid_t>(-1)) {
        return "system";
    }

    struct passwd* pw = getpwuid(auid);
    std::string username = pw ? pw->pw_name : "unknown";

    if (euid == 0 && auid != 0) {
        username += "+root";
    }

    return username;
}
std::string extract_exec_argc(const std::string& msg) {
    static const std::regex argc_regex(R"(argc=(\d+))");
    std::smatch match;
    int argc = 0;

    if (std::regex_search(msg, match, argc_regex)) {
        argc = std::stoi(match[1]);
    } else {
        return "";
    }

    std::string result;
    for (int i = 0; i < argc; ++i) {
        std::string arg_pattern = "a" + std::to_string(i) + R"(=\"([^\"]*)\")";
        std::regex arg_regex(arg_pattern);
        if (std::regex_search(msg, match, arg_regex)) {
            result += match[1].str() + " ";
        }
    }

    if (!result.empty())
        result.pop_back();

    return result;
}
std::string extract_audit_timestamp(const std::string& msg) {
    static const std::regex timestamp_regex(R"(audit\((\d+)\.(\d+):\d+\))");
    std::smatch match;

    if (std::regex_search(msg, match, timestamp_regex) && match.size() > 2) {
        try {
            std::time_t seconds = std::stoll(match[1]);
            std::tm* gmtimePtr = std::gmtime(&seconds);

            std::ostringstream oss;
            oss << std::put_time(gmtimePtr, "%Y-%m-%dT%H:%M:%SZ");
            // std::cout << "время взял";
            return oss.str();
        } catch (...) {
            return "invalid_time";
        }
    }

    return "unknown_time";
}
std::string extract_event_id(const std::string& msg) {
    static const std::regex id_regex(R"(audit\([^:]+:(\d+)\))");
    std::smatch match;
    if (std::regex_search(msg, match, id_regex)) {
        return match[1];
    }
    return "";
}
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

void write_log_entry(const LogEntry& e){
    std::ofstream logfile("/home/client/Desktop/log.txt", std::ios::app);
    if (logfile.is_open()) {
        logfile << e;
        std::cout << e;
        logfile.close();
    } else {
        std::cerr << "❌ Ошибка при открытии log-файла\n";
    }
}