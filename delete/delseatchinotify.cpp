#include <iostream>
#include <sys/inotify.h>
#include <unistd.h>
#include <cstdlib>
#include <unordered_map>
#include <ctime>
#include <cstring>
#include <vector>
#include <unordered_map>
// Функция для получения текущей даты и времени в формате "Apr 18 13:11:59"
std::string get_current_time() {
    char buffer[80];
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S", timeinfo);
    return std::string(buffer);
}

int main() {
    int fd = inotify_init();
    if (fd == -1) {
        std::cerr << "Error initializing inotify" << std::endl;
        return -1;
    }

    // Директории, за которыми следим
    std::vector<std::string> dirs_to_watch = {
        "/home/kartoger/DiplomaAgents/delete",
        "/home/kartoger/DiplomaAgents/delete2"
    };

    // Сопоставление watch descriptor -> путь к директории
    std::unordered_map<int, std::string> wd_to_dir;

    for (const auto& dir : dirs_to_watch) {
        int wd = inotify_add_watch(fd, dir.c_str(), IN_MODIFY | IN_DELETE);
        if (wd == -1) {
            std::cerr << "Error adding watch for " << dir << std::endl;
            close(fd);
            return -1;
        }
        wd_to_dir[wd] = dir; // безопасно связываем
    }

    char buffer[1024];
    while (true) {
        int length = read(fd, buffer, sizeof(buffer));
        if (length == -1) {
            std::cerr << "Error reading events" << std::endl;
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];

            std::string event_type;
            if (event->mask & IN_MODIFY) {
                event_type = "[MODIFY]";
            } else if (event->mask & IN_DELETE) {
                event_type = "[DELETE]";
            }

            std::string current_time = get_current_time();
            const char* username = getenv("USER");

            // Безопасно получаем директорию
            std::string dir = wd_to_dir.count(event->wd) ? wd_to_dir[event->wd] : "Unknown";

            std::cout << current_time << "  " << event_type
                      << ": " << dir << "/" << event->name
                      << " " << event_type << " by " << username << std::endl;

            i += sizeof(struct inotify_event) + event->len;
        }
    }

    close(fd);
    return 0;
}
