#include <iostream>
#include <fstream>
#include <string>
#include <regex>

std::string getMacAddress() {
    std::ifstream macFile("/sys/class/net/enp0s3/address");
    if (!macFile.is_open()) {
        std::cerr << "Не удалось открыть файл MAC-адреса!" << std::endl;
        return "unknown";
    }
    std::string mac;
    std::getline(macFile, mac);
    macFile.close();
    return mac;
}

std::string getTime(std::string& line) {
    // Регулярка для времени (в начале строки)
    std::regex timeRegex(R"(^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}))");
    std::smatch timematch;
    if (std::regex_search(line, timematch, timeRegex)) {
        return timematch[1];
    }
    else {
        return "unknown";
    }
}
std::string getUser(std::string& line) {
   std::regex re_invalid(R"(Failed password for (\w+))");
    std::smatch usermatch;
        if (std::regex_search(line, usermatch, re_invalid)){
            return usermatch[1];
        } else {
            return "unknown";
        }
}
int main() {
    std::string log="2025-04-10T11:48:42.523029+05:00 kartoger-VirtualBox sshd[9918]: Failed password for BAdsa_ds2 from 10.59.68.24 port 59840 ssh2";
    std::string Mac = getMacAddress();
    std::string user = getUser(log);
    std::string time = getTime(log);
    std::cout <<"Time: " << time << ", Mac: " << Mac << ", User: " << user << std::endl;
}
