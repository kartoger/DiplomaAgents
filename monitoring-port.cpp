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

// Проверка: является ли IP адрес внутренним
bool isPrivateIP(const std::string& ip) {
    struct in_addr addr;
    inet_aton(ip.c_str(), &addr);
    uint32_t ipnum = ntohl(addr.s_addr);

    return
        (ipnum >> 24) == 10 ||                                // 10.0.0.0/8
        (ipnum >> 20) == (172 << 4 | 1) ||                    // 172.16.0.0/12
        (ipnum >> 16) == (192 << 8 | 168) ||                  // 192.168.0.0/16
        ip == "127.0.0.1";                                    // localhost
}

// Анализ соединений
void scanConnections(std::unordered_map<std::string, std::vector<int>>& ipPorts) {
    std::ifstream tcpFile("/proc/net/tcp");
    std::string line;
    getline(tcpFile, line); // пропустить заголовок

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

        // Пропускаем внутренние IP-адреса
        if (isPrivateIP(ipStr)) continue;

        ipPorts[ipStr].push_back(port);
    }
}

void detectPortScanning(const std::unordered_map<std::string, std::vector<int>>& ipPorts) {
    for (const auto& entry : ipPorts) {
        const std::string& ip = entry.first;
        const std::vector<int>& ports = entry.second;

        if (ports.size() >= 5) { // если IP подключается к >= 5 портам
            std::cout << "Внешний IP-адрес сканирует порты: " << ip
                      << " (попыток: " << ports.size() << ")\n";
        }
    }
}

int main() {
    std::cout << "Мониторинг внешнего сканирования портов...\n";

    while (true) {
        std::unordered_map<std::string, std::vector<int>> ipPorts;
        scanConnections(ipPorts);
        detectPortScanning(ipPorts);
        sleep(3); // периодичность проверки
    }

    return 0;
}
