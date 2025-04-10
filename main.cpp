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

std::string getUser(std::string& line) {
   std::regex re_invalid(R"(Failed password for (\w+))");
    std::smatch match;
        if (std::regex_search(line, match, re_invalid)){
            return match[1];
        } else {
            return "unknown";
        }

}
int main() {
    std::string log="2025-04-10T11:48:42.523029+05:00 kartoger-VirtualBox sshd[9918]: Failed password for BAdsa_ds2 from 10.59.68.24 port 59840 ssh2";
    std::string Mac = getMacAddress();
    std::string user = getUser(log);
    std::cout << "Mac: " << Mac << ", User: " << user << std::endl;
}

