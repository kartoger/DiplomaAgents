#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <ifaddrs.h>
#include <filesystem>
#include <fstream>
#include <libud/libudev.h> // sudo apt install libudev-dev
#include <sys/inotify.h>

#include <magic.h> // sudo apt install libmagic-dev
// Фильтрация событий
std::string global_typename = "none";
std::string getTimestamp1() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

// Чтение MAC-адреса из sysfs
std::string getMacAddress2() {
    std::ifstream file("/sys/class/net/enp3s0/address");
    std::string mac;
    if (file.is_open()) {
        std::getline(file, mac);
    } else {
        mac = "00:00:00:00:00:00";
    }
    return mac;
}
void write_log_gsa(std::string timestamp = "none",
                  std::string mac = "none",
                  std::string event_name = "none" ,
                  std::string event_type = "none",
                  std::string username = "",
                  std::string details = "none") {
    if (timestamp == "") {
        timestamp = getTimestamp1();
    }
    if (mac == "") {
        mac = getMacAddress2();
    }
    if (username == "") {
        username = getlogin();
    }
    std::cout << "[" << timestamp    << "] "
              << "[" << mac   << "] "
              << "[" << event_name << "::" << event_type    << "] "
              << "[" << username << "] "
              << "[" << details           << "]\n";



    // const char* user = getlogin();
    // std::cout << "[" << timestamp    << "] "
    //           << "[" << mac   << "] "
    //           << "[" << event_name         << "] "
    //           << "[" << (user? user:"unknown") << "] "
    //           << "[" << details           << "]\n";
}
bool filter_event(const std::string& line) {
    if (line.find("\"SYSLOG_IDENTIFIER\":\"gdm-password]\"") != std::string::npos &&
        (line.find("pam_unix(gdm-password:session)") != std::string::npos ||
         line.find("pam_unix(gdm-password:auth)") != std::string::npos))
    {
        global_typename = "gdm-password";
        return line.find("\"MESSAGE\":\"") != std::string::npos;
    }

    if (line.find("\"SYSLOG_IDENTIFIER\":\"sshd\"") != std::string::npos &&
        ((line.find("pam_unix(sshd:session)") != std::string::npos && line.find("session opened") == std::string::npos) ||
         line.find("Accepted password") != std::string::npos ||
         line.find("Accepted publickey") != std::string::npos ||
         line.find("Failed password") != std::string::npos))
        //         line.find("Invalid user") != std::string::npos))
    {
        global_typename = "sshd";
        return line.find("\"MESSAGE\":\"") != std::string::npos;
    }

    return false;
}

std::string extract_time(const std::string& line) {
    size_t pos = line.find("\"__REALTIME_TIMESTAMP\":\"");
    if (pos != std::string::npos) {
        pos += strlen("\"__REALTIME_TIMESTAMP\":\"");
        size_t end_pos = line.find("\"", pos);
        return line.substr(pos, end_pos - pos);
    }
    return "none";
}
std::string format_timestamp(const std::string& timestamp_str) {
    if (timestamp_str == "none" || timestamp_str.empty()) return "none";
    uint64_t microseconds = std::stoull(timestamp_str);
    time_t seconds = microseconds / 1000000;
    struct tm* timeinfo = gmtime(&seconds);
    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", timeinfo);
    return std::string(buffer);
}

std::string extract_message(const std::string& line) {
    size_t pos = line.find("\"MESSAGE\":\"");
    if (pos != std::string::npos) {
        pos += strlen("\"MESSAGE\":\"");
        size_t end_pos = line.find("\"", pos);
        return line.substr(pos, end_pos - pos);
    }
    return "";
}

std::string determine_gdm_event_type(const std::string& message) {
    if (message.find("authentication failure") != std::string::npos) return "Failed";
    if (message.find("session opened") != std::string::npos) return "Success";
    if (message.find("session closed") != std::string::npos) return "Closed";
    return "none";
}

std::string extract_gdm_username(const std::string& message, const std::string& event_type) {
    std::string username = "none";
    if (event_type == "Success" || event_type == "Closed") {
        size_t user_pos = message.find(" user ");
        if (user_pos != std::string::npos) {
            user_pos += strlen(" user ");
            size_t end_pos = message.find("(", user_pos);
            username = message.substr(user_pos, end_pos - user_pos);
        }
    } else if (event_type == "Failed") {
        size_t user_pos = message.find(" user=");
        if (user_pos != std::string::npos) {
            user_pos += strlen(" user=");
            size_t end_pos = message.find("\"", user_pos);
            username = message.substr(user_pos, end_pos - user_pos);
        }
    }
    return username;
}



// === Обработка событий от SSHD ===
std::string determine_sshd_event_type(const std::string& message) {
    if (message.find("authentication failure") != std::string::npos || message.find("Failed password") != std::string::npos) return "Failed";
    if (message.find("session opened") != std::string::npos || message.find("Accepted password") != std::string::npos || message.find("Accepted publickey") != std::string::npos) return "Success";
    if (message.find("session closed") != std::string::npos) return "Closed";
    // if (message.find("Invalid user") != std::string::npos) return "InvalidUser";
    return "none";
}

std::string extract_sshd_username(const std::string& message, const std::string& event_type) {
    std::string username = "none";
    if (event_type == "Failed" || event_type == "Success") {
        size_t pos = message.find(" for ");
        if (pos != std::string::npos) {
            pos += strlen(" for ");
            size_t end_pos = message.find(" from", pos);
            username = message.substr(pos, end_pos - pos);
            if (username.find("invalid user") != std::string::npos){
                size_t invalid_pos = strlen("invalid user ");
                username = "InvalidUser:" + username.substr(invalid_pos);
            }
        }
    }
    else if (event_type == "Closed"){
        size_t user_pos = message.find(" user ");
        if (user_pos != std::string::npos  ) {
            user_pos += strlen(" user ");
            size_t end_pos = message.find("\"", user_pos);
            username = message.substr(user_pos,end_pos-user_pos);
        }
    }
    else if (event_type == "InvalidUser") {
        username = "InvalidUser";
    }
    return username;
}
std::string extract_sshd_details(const std::string& message) {
    size_t ip_pos = message.find(" from ");
    if (ip_pos != std::string::npos) {
        ip_pos += strlen(" from ");
        size_t port_pos = message.find(" port ", ip_pos);
        if (port_pos != std::string::npos) {
            std::string ip = message.substr(ip_pos, port_pos - ip_pos);
            port_pos += strlen(" port ");
            size_t ssh_pos = message.find(" ssh2", port_pos);
            if (ssh_pos != std::string::npos) {
                std::string port = message.substr(port_pos, ssh_pos - port_pos);
                return ip + ":" + port;
            }
        }
    }
    return "unknown SSH login";
}
void handle_sshd_event(const std::string& line) {
    std::string message = extract_message(line);
    std::string event_type = determine_sshd_event_type(message);
    std::string username = extract_sshd_username(message, event_type);
    std::string details = extract_sshd_details(message);
    std::string timestamp = extract_time(line);


    // print_event(timestamp, "sshd", event_type, username, details);
}
void handle_gdm_event(const std::string& line) {
    std::string message = extract_message(line);
    std::string event_type = determine_gdm_event_type(message);
    std::string username = extract_gdm_username(message, event_type);
    std::string details = "local GUI login";
    std::string timestamp = extract_time(line);

    write_log_gsa(timestamp,"", "gdm-password", event_type, username, details);

    // print_event(timestamp, "gdm-password", event_type, username, details);
}
// === Главный обработчик событий ===
void handle_event(const std::string& line) {


    // ДЛЯ DEBUG
    // std::cout << "[MATCH] " << line << std::endl;
    // std::cout << std::string(20, '*') << std::endl;
    if (global_typename == "gdm-password") {
        handle_gdm_event(line);
    } else if (global_typename == "sshd") {
        handle_sshd_event(line);
    } else {
        std::cerr << "[ERROR] Неизвестный источник события!\n";
    }
}

// === Чтение событий из journalctl ===
void ssh_gdm_monitoring() {
    FILE* pipe = popen("/bin/sh -c '/usr/bin/journalctl -f -o json'", "r");
    if (!pipe) {
        std::cerr << "[ERROR] Не удалось открыть поток journalctl" << std::endl;
        return;
    }

    char buffer[4096];
    // std::cout << "[INFO] Стартing чтения событий journalctl...\n";

    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        if (filter_event(line)) {
            handle_event(line);
        }
    }
    pclose(pipe);
}