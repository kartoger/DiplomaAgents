#include <iostream>
#include <fstream>
#include <string>

int main() {
      std::ifstream macFile("/sys/class/net/enp0s3/address");
      if (!macFile.is_open()) {
          std::cerr << "Не удалось открыть файл MAC-адреса!" << std::endl;
          return 1;
      }
    char buffer[128];
    std::string resultuser = "";
    FILE* user = popen("whoami", "r");
    while (fgets(buffer, sizeof(buffer), user) != nullptr) {
        resultuser += buffer;
    }
    pclose(user);

    std::string mac;
      std::getline(macFile, mac);
      macFile.close();
      int Time = 0;

      std::cout << "MAC: " << mac << ", Time: " << Time << ", User: " << resultuser <<  std::endl;
      return 0;
  }
