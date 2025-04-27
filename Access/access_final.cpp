#include <iostream>
#include <cstdio>
#include <string>
#include <cstring>
#include <fstream>
#include <cstdint>

// Преобразование microsecond timestamp в ISO 8601 строку
std::string format_timestamp(const std::string& timestamp_str) {
    if (timestamp_str == "none" || timestamp_str.empty()) {
        return "none";
    }

    uint64_t microseconds = std::stoull(timestamp_str);
    time_t seconds = microseconds / 1000000; // Переводим в секунды

    struct tm* timeinfo = gmtime(&seconds); // UTC время

    char buffer[30];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", timeinfo); // ISO 8601

    return std::string(buffer);
}
// Фильтрация события: оставляем только строки, содержащие "gdm-password:session" или "gdm-password:auth"
bool filter_event(const std::string& line) {
    if (line.find("pam_unix(gdm-password:session)") != std::string::npos ||
        line.find("pam_unix(gdm-password:auth)") != std::string::npos) {
        return line.find("\"MESSAGE\":\"") != std::string::npos;
    }
    return false;
}
// Извлечение mac адреса из системы 
std::string extract_mac(const std::string& interface) {
    std::string path = "/sys/class/net/" + interface + "/address";
    std::ifstream file(path);

    if (!file.is_open()) {
        std::cerr << "[ERROR] Не удалось открыть файл: " << path << std::endl;
        return "none";
    }
    std::string mac_address;
    std::getline(file, mac_address); // Считываем первую строку
    file.close();
    
    return mac_address;
}

// Извлечение timestamp из строки
std::string extract_time(const std::string& line) {
  std::string timestamp = "none";
  size_t pos = line.find("\"__REALTIME_TIMESTAMP\":\"");
  if (pos != std::string::npos) {
    pos += strlen("\"__REALTIME_TIMESTAMP\":\"");
    size_t end_pos = line.find("\"", pos);
    timestamp = line.substr(pos,end_pos - pos);
    
  } 
  return timestamp;
}
// Извлечение username из строки
std::string extract_username(const std::string& line,std::string event_type) {
std::string username = "none";
if (event_type == "failed"){
  size_t user_pos = line.find(" user=");
  if (user_pos != std::string::npos) {
    user_pos += strlen(" user="); 
    size_t end_pos = line.find("\"", user_pos);
    username = line.substr(user_pos,end_pos-user_pos);    
  }
}
else if (event_type == "success"){
  size_t user_pos = line.find(" user ");
  if (user_pos != std::string::npos) {
    user_pos += strlen(" user "); 
    size_t end_pos = line.find("(", user_pos);
    username = line.substr(user_pos,end_pos-user_pos);    
    }
  }
else if (event_type == "closed"){
  size_t user_pos = line.find(" user ");
  if (user_pos != std::string::npos  ) {
    user_pos += strlen(" user "); 
    size_t end_pos = line.find("\"", user_pos);
    username = line.substr(user_pos,end_pos-user_pos);    
    }
  }
    return username;
}



//Извлечение текствого поля message
std::string extract_message(const std::string& line) {
    size_t message_pos = line.find("\"MESSAGE\":\"");
    if (message_pos != std::string::npos) {
        message_pos += strlen("\"MESSAGE\":\"");
        size_t end_pos = line.find("\"", message_pos);
        return line.substr(message_pos, end_pos - message_pos);
    }
    return "";
}


//Извлечение типа события
std::string extract_typevent(const std::string& message) {
    if (message.find("authentication failure") != std::string::npos) {
        return "failed";
    }
    if (message.find("session opened") != std::string::npos) {
        return "success";
    }
    if (message.find("session closed") != std::string::npos) {
        return "closed";
    }
    
    return "none"; // Ничего не нашли
}

// Обработка события (пока просто вывод на экран)
void handle_event(const std::string& line) {
    std::string line_from_message = extract_message(line);
    std::string event_name = "gdm_password";
    std::string event_type = extract_typevent(line_from_message);
    std::string username = extract_username(line_from_message,event_type);
    std::string timestamp = extract_time(line);
    std::string formatted_time = format_timestamp(timestamp);
    std::string mac = extract_mac("enp0s3");
    
    std::cout << "[MATCH] " << line << std::endl;
    std::cout << std::string(20, '*') << std::endl;
    std::cout << "User: " << extract_username(extract_message(line),event_type)<< std::endl;
    std::cout << "Timestamp: " << extract_time(line) << std::endl;
    std::cout << "MAC: " << extract_mac("enp0s3") << std::endl;
    std::cout << event_name << "::" << event_type << std::endl;
    std::cout << std::string(20, '*') << std::endl << std::endl;
    
    std::cout << "...Нужный формат..." << std::endl;
    std::cout << "[" << formatted_time << "] "
              << "[" << mac << "] "
              << "[" <<  event_name << "::" << event_type << "] "
              << "[" << username << "] "
              << "[" << "local GUI login" << "]" << std::endl << std::endl;
}





// Чтение событий из journalctl
void read_journal() {
    FILE* pipe = popen("/bin/sh -c '/usr/bin/journalctl -f -o json'", "r");
    if (!pipe) {
        std::cerr << "[ERROR] Не удалось открыть поток journalctl" << std::endl;
        return;
    }

    char buffer[4096];

    std::cout << "[INFO] Старт чтения событий journalctl..." << std::endl;

    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);

        if (filter_event(line)) {
            handle_event(line);
        }
    }

    pclose(pipe);
}


int main() {
    read_journal();
    return 0;
}