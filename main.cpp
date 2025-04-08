#include <iostream>
#include <fstream>
#include <string>

int main() {
    std::ifstream macFile("/sys/class/net/enp0s3/address");
    if (!macFile.is_open()) {
        std::cerr << "Не удалось открыть файл MAC-адреса!" << std::endl;
        return 1;
    }
    std::string mac;
    std::getline(macFile, mac);
    macFile.close();
    int Time = 0;
    std::string user = "XXXXXXXXX";
    std::cout << "MAC:" << mac << "Time:" << Time << "User" << user <<  std::endl;
    return 0;
}
