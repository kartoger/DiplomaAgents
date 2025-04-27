#include <iostream>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/inotify.h>
#include <regex>

#define EVENT_SIZE      (sizeof(struct inotify_event))
#define EVENT_BUF_LEN   (1024 * (EVENT_SIZE + 16))

void process_recent_lines() {
    FILE* pipe = popen("tail -n 10 /var/log/auth.log", "r");
    if (!pipe) {
        std::cerr << "[ERROR] Не удалось открыть tail" << std::endl;
        return;
    }

    char buffer[512];
    std::regex repeat_re(R"(message repeated (\d+) times: \[ (.+) \])");

    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        std::cout << "[DEBUG] Читаем: " << line;

        if (line.find("gdm-password") == std::string::npos) {
            std::cout << "[DEBUG] Пропущено: не gdm-password" << std::endl;
            continue;
        }

        if (line.find("authentication failure;") != std::string::npos) {
            std::cout << "[FAILED]  " << line;
        }
        else if (line.find("session opened for user") != std::string::npos) {
            std::cout << "[SUCCESS] " << line;
        }
        else if (line.find("message repeated") != std::string::npos) {
            std::smatch match;
            if (std::regex_search(line, match, repeat_re)) {
                int repeat_count = std::stoi(match[1]);
                std::string repeated_msg = match[2];
                std::cout << "[DEBUG] Повтор " << repeat_count << " раз: " << repeated_msg << std::endl;

                if (repeated_msg.find("authentication failure;") != std::string::npos) {
                    for (int i = 0; i < repeat_count; ++i)
                        std::cout << "[FAILED]  " << repeated_msg << std::endl;
                }
                if (repeated_msg.find("session opened for user") != std::string::npos) {
                    for (int i = 0; i < repeat_count; ++i)
                        std::cout << "[SUCCESS] " << repeated_msg << std::endl;
                }
            }
        } else {
            std::cout << "[DEBUG] Пропущено: не распознано" << std::endl;
        }
    }

    pclose(pipe);
}

void monitor_auth_log() {
    const std::string log_path = "/var/log/auth.log";

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        perror("[ERROR] inotify_init");
        return;
    }

    int wd = inotify_add_watch(fd, log_path.c_str(), IN_MODIFY);
    if (wd == -1) {
        std::cerr << "[ERROR] Не удалось добавить наблюдение" << std::endl;
        close(fd);
        return;
    }

    char buffer[EVENT_BUF_LEN];
    std::cout << "[INFO] Агент работает. Ожидаем события..." << std::endl;

    while (true) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            usleep(100000);
            continue;
        }

        std::cout << "[DEBUG] inotify: файл изменён" << std::endl;
        process_recent_lines();
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

int main() {
    monitor_auth_log();
    return 0;
}
