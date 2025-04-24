#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <ctime>
#include <arpa/inet.h>
#include <unistd.h>

// Преобразуем IP из hex в читаемый формат
std::string hexToIp(const std::string& hex) {
    unsigned int ip;
    std::stringstream ss;
    ss << std::hex << hex;
    ss >> ip;
    ip = ntohl(ip);

    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

// Анализ входящих соединений
void scanConnections(std::unordered_map<std::string, std::vector<int>>& ipPorts) {
    std::ifstream tcpFile("/proc/net/tcp");
    std::string line;
    getline(tcpFile, line); // заголовок

    while (getline(tcpFile, line)) {
        std::istringstream iss(line);
        std::string sl, localAddr, remoteAddr, state;
        iss >> sl >> localAddr >> remoteAddr >> state;

        if (state != "01") continue; // только ESTABLISHED

        std::string remoteIPHex = remoteAddr.substr(0, remoteAddr.find(":"));
        std::string remotePortHex = remoteAddr.substr(remoteAddr.find(":") + 1);

        int port;
        std::stringstream ss;
        ss << std::hex << remotePortHex;
        ss >> port;

        std::string ipStr = hexToIp(remoteIPHex);
        ipPorts[ipStr].push_back(port);
    }
}

void detectPortScanning(const std::unordered_map<std::string, std::vector<int>>& ipPorts) {
    for (const auto& entry : ipPorts) {
        const std::string& ip = entry.first;
        const std::vector<int>& ports = entry.second;

        if (ports.size() >= 10) { // если IP лезет к >10 портам
            std::cout << "Возможное сканирование портов от IP: " << ip
                      << " (попытки к " << ports.size() << " портам)" << std::endl;
        }
    }
}

int main() {
    std::cout << "🛡 Мониторинг порт-сканирования..." << std::endl;

    while (true) {
        std::unordered_map<std::string, std::vector<int>> ipPorts;
        scanConnections(ipPorts);
        detectPortScanning(ipPorts);
        sleep(3); // задержка между циклами
    }

    return 0;
}
