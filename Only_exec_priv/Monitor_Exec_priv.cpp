#include <iostream>
#include <libaudit.h>
#include <unistd.h>
#include <cstring>
#include <unordered_set>
#include <unordered_map>
#include <regex>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <pwd.h>
#include <chrono>
#include <sstream>
#include <fstream>



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
std::string extract_auid_username(const std::string& msg) {
    static const std::regex uid_regex(R"(uid=(\d+))");
    static const std::regex euid_regex(R"(euid=(\d+))");
    static const std::regex auid_regex(R"(auid=(\d+))");

    std::smatch match_uid, match_auid, match_euid;

    uid_t uid = -1;
    uid_t auid = -1;
    uid_t euid = -1;

    if (std::regex_search(msg, match_auid, auid_regex)) {
        auid = std::stoi(match_auid[1]);
    }
    if (std::regex_search(msg, match_uid, uid_regex)) {
        uid = std::stoi(match_uid[1]);
    }
    if (std::regex_search(msg, match_euid, euid_regex)) {
        euid = std::stoi(match_euid[1]);
    }

    struct passwd* pw = getpwuid(auid);
    std::string username = pw ? pw->pw_name : "unknown";

    if (euid == 0 && auid != 0) {
        username += "+root";
    }

    return username;
}
std::string extract_exe_path(const std::string& msg) {
    static const std::regex exe_regex(R"(exe=\"([^\"]+)\")");
    std::smatch match;
    if (std::regex_search(msg, match, exe_regex)) {
        return match[1];
    }
    return "";
}



std::string extract_cwd_path(const std::string& msg) {
    static const std::regex cwd_regex(R"(cwd=\"([^\"]+)\")");
    std::smatch match;
    if (std::regex_search(msg, match, cwd_regex)) {
        return match[1];
    }
    return "";
}

std::string extract_exec(const std::string& msg) {
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

std::string extract_event_id(const std::string& msg) {
    static const std::regex id_regex(R"(audit\([^:]+:(\d+)\))");
    std::smatch match;
    if (std::regex_search(msg, match, id_regex)) {
        return match[1];
    }
    return "";
}

std::string extract_timestamp(const std::string& msg) {
    static const std::regex ts_regex(R"(audit\((\d+\.\d+):\d+\))");
    std::smatch match;
    if (std::regex_search(msg, match, ts_regex)) {
        return match[1];
    }
    return "";
}

struct ExecEventGroup {
    std::string exec_path;
    std::string cwd_path;
    std::string full_comand;
    std::string timestamp;
    std::string username;

};
std::string getTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
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

std::ostream& operator<<(std::ostream& os, const LogEntry& e) {
    return os
        << "[" << e.timestamp    << "] "
        << "[" << e.mac          << "] "
        << "[" << e.event_name
        <<  "::" << e.event_type << "] "
        << "[" << e.username     << "] "
        << "[" << e.details      << "]" << std::endl;
}

int main() {
    int audit_fd = audit_open();


    if (audit_set_pid(audit_fd, getpid(), WAIT_YES) <= 0) {
        std::cerr << "Не удалось зарегистрироваться как audit-демон\n";
        return 1;
    }
    if (audit_fd < 0) {
        std::cerr << "Не удалось подключиться к audit-сокету\n";
        return 1;
    }

    std::cout << "Ожидание событий с ключом [exec_priv]...\n";

    std::unordered_set<int> allowed_types = {
        1300, // SYSCALL
        1302, // PATH
        1307, // CWD
        1309, // EXECVE
        1327  // PROCTITLE
    };

    std::unordered_map<int, std::string> type_names = {
        {1300, "SYSCALL"},
        {1302, "PATH"},
        {1307, "CWD"},
        {1309, "EXECVE"},
        {1327, "PROCTITLE"}
    };

    std::unordered_map<std::string, ExecEventGroup> event_groups;

    struct audit_reply rep;
    while (true) {
        memset(&rep, 0, sizeof(rep));

        int rc = audit_get_reply(audit_fd, &rep, GET_REPLY_BLOCKING, 0);
        if (rc <= 0) {
            std::cerr << "Ошибка чтения события аудита\n";
            break;
        }

        std::string msg = rep.message ? rep.message : "";
        std::string event_id = extract_event_id(msg);

        if (allowed_types.count(rep.type) > 0 && !event_id.empty()) {
            ExecEventGroup& group = event_groups[event_id];

            if (rep.type == 1300) {
                group.exec_path = extract_exe_path(msg);
                group.username=extract_auid_username(msg);
                // std::cout << msg << "\n";
                group.timestamp = extract_timestamp(msg);
            } else if (rep.type == 1307) {
                group.cwd_path = extract_cwd_path(msg);
            } else if (rep.type == 1309) {
                group.full_comand = extract_exec(msg);
            }

            if (!group.exec_path.empty() && !group.cwd_path.empty() && !group.full_comand.empty() && !group.timestamp.empty()) {
                std::ostringstream oss;
                oss << "time=" << group.timestamp
                    << ", exec_path=\"" << group.exec_path
                    << "\", cwd_path=\"" << group.cwd_path
                    << "\", user=\"" << group.username
                    << "\", full_comand=\"" << group.full_comand << "\"";
                std::cout << oss.str() << std::endl;


                std::cout << LogEntry{
                    .timestamp = group.timestamp,
                    .event_name = "Terminal",

                    .event_type = "execve",
                    .username = group.username,
                    .details = "cwd_path=" + group.cwd_path+", exec_path=" + group.exec_path+", full_comand=" + group.full_comand
                };
                event_groups.erase(event_id);






            }
        }
    }

    close(audit_fd);
    return 0;
}
