#include <iostream>
#include <unistd.h>
#include <filesystem>
#include <fstream>
std::string getTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}
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
void write_log(std::string timestamp = "none",
                  std::string mac = "none",
                  std::string event_name = "none" ,
                  std::string event_type = "none",
                  std::string username = "",
                  std::string details = "none") {
    if (timestamp == "") {
        timestamp = getTimestamp();
    }
    if (mac == "") {
        mac = getMacAddress();
    }
    if (username == "") {
        username = getlogin();
    }
    std::cout << "[" << timestamp    << "] "
              << "[" << mac   << "] "
              << "[" << event_name << "::" << event_type    << "] "
              << "[" << username << "] "
              << "[" << details           << "]\n";

}