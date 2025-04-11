#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

std::string getUsername(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (pw) return std::string(pw->pw_name);
    return "unknown";
}

void watchCriticalFolders(const std::string& path) {
    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        return;
    }

    int wd = inotify_add_watch(fd, path.c_str(), IN_DELETE | IN_DELETE_SELF);
    if (wd == -1) {
        std::cerr << "Не удалось следить за: " << path << std::endl;
        return;
    } else {
        std::cout << "Следим за: " << path << std::endl;
    }

    char buffer[EVENT_BUF_LEN];
    while (true) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read");
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            if (event->mask & IN_DELETE) {
                std::cout << "Обнаружено удаление файла: " << event->name << " в " << path << std::endl;

                uid_t uid = geteuid(); // Кто запустил процесс
                std::string user = getUsername(uid);

                // Логируем
                std::ofstream logfile("critical_delete.log", std::ios::app);
                logfile << "Пользователь: " << user << " удалил " << event->name << " в " << path << std::endl;
                logfile.close();
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

int main() {
    std::string paths[] = {"/etc", "/bin", "/sbin", "/usr"};

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid > 0) {
        // Родитель завершает работу
        return 0;
    } else {
        // Дочерний процесс становится демоном
        setsid();
        chdir("/");
        umask(0);

        for (const auto& path : paths) {
            if (fork() == 0) {
                watchCriticalFolders(path);
                exit(0);
            }
        }
        while (true) {
            sleep(60);
        }
    }

    return 0;
}
