#include <iostream>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <cstring>
#include <map>
#include <filesystem>
#include <vector>
#include <fstream>
#include <pwd.h>
#include <chrono>
#include <ctime>
#include <system_error>
#include "For_all.h"
namespace fs = std::filesystem;
// --- Добавление слежения за директорией ---
void add_watch(int inotify_fd, const std::string& path, std::map<int, std::string>& watches) {
    int wd = inotify_add_watch(inotify_fd, path.c_str(), IN_CREATE | IN_DELETE | IN_MODIFY);
    if (wd == -1) {
        std::cerr << "[WARN] Ошибка добавления " << path << ": " << strerror(errno) << std::endl;
    } else {
        watches[wd] = path;
        std::cout << "[WATCHING] " << path << std::endl;
    }
}

// --- Получение владельца файла ---
std::string get_file_owner(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return "unknown";
    }
    struct passwd* pw = getpwuid(info.st_uid);
    if (pw) {
        return std::string(pw->pw_name);
    }
    return "unknown";
}
// --- Фильтрация директорий (на уровне слежения) ---
bool should_skip_directory(const std::string& path) {
    return path.find("/.config/") != std::string::npos ||
           path.find("/snap/") != std::string::npos ||
           path.find("/.local/") != std::string::npos ||
           path.find("/.cache/") != std::string::npos ||
           path.find("/.git/") != std::string::npos;
}
// --- Фильтрация событий (на уровне событий) ---
bool should_skip_event(const std::string& path) {
    return path.find("/.config/") != std::string::npos ||
           path.find("/snap/") != std::string::npos ||
           path.find("/.local/") != std::string::npos ||
           path.find("/.cache/") != std::string::npos ||
           path.find("/.git/") != std::string::npos;
}
bool is_temporary_editor_file(const std::string& filename) {
    return filename.ends_with(".swp") ||
           filename.ends_with(".tmp") ||
           filename.ends_with(".bak") ||
           filename.ends_with(".swx");
}
bool should_monitor_config_subdir(const std::string& path) {
    return path.find("/.config/dconf/") != std::string::npos ||
           path.find("/.config/evolution/") != std::string::npos ||
           path.find("/.config/gnome-session/") != std::string::npos ||
           path.find("/.config/goa-1.0/") != std::string::npos ||
           path.find("/.config/systemd/") != std::string::npos;
}
bool should_monitor_etc_subdir(const std::string& path) {
    return
        // Файлы пользователей и паролей
        path == "/etc/passwd" ||
        path == "/etc/shadow" ||
        path == "/etc/group" ||
        path == "/etc/gshadow" ||
        path == "/etc/sudoers" ||
        path.find("/etc/sudoers.d/") == 0 ||
        path.find("/etc/sudoers.d") == 0 ||

        // Конфиги SSH
        path.find("/etc/ssh/") == 0 ||
        path.find("/etc/ssh") == 0 ||

        // Конфиги PAM
        path.find("/etc/pam.d") == 0 ||
        path.find("/etc/pam.d/") == 0 ||

        // Аудит безопасности
        path.find("/etc/audit/") == 0 ||

        // Автозадания

        path.find("/etc/cron.d") == 0 ||
        path.find("/etc/cron.daily") == 0 ||
        path.find("/etc/cron.hourly") == 0 ||
        path.find("/etc/cron.weekly") == 0 ||
        path.find("/etc/cron.monthly") == 0 ||
        path.find("/etc/cron.yearly") == 0 ||
        path.find("/etc/cron.d/") == 0 ||
        path.find("/etc/cron.daily/") == 0 ||
        path.find("/etc/cron.hourly/") == 0 ||
        path.find("/etc/cron.weekly/") == 0 ||
        path.find("/etc/cron.monthly/") == 0 ||
        path.find("/etc/cron.yearly/") == 0 ||

        // Автозапуски сервисов
        path.find("/etc/systemd") == 0 ||
        path.find("/etc/init.d") == 0 ||
        path.find("/etc/rc0.d") == 0 ||
        path.find("/etc/rc1.d") == 0 ||
        path.find("/etc/rc2.d") == 0 ||
        path.find("/etc/rc3.d") == 0 ||
        path.find("/etc/rc4.d") == 0 ||
        path.find("/etc/rc5.d") == 0 ||
        path.find("/etc/rc6.d") == 0 ||

        path.find("/etc/systemd/") == 0 ||
        path.find("/etc/init.d/") == 0 ||
        path.find("/etc/rc0.d/") == 0 ||
        path.find("/etc/rc1.d/") == 0 ||
        path.find("/etc/rc2.d/") == 0 ||
        path.find("/etc/rc3.d/") == 0 ||
        path.find("/etc/rc4.d/") == 0 ||
        path.find("/etc/rc5.d/") == 0 ||
        path.find("/etc/rc6.d/") == 0 ||

        // Сетевые настройки
        path.find("/etc/netplan") == 0 ||
        path.find("/etc/network/") == 0 ||
        path.find("/etc/network") == 0 ||
        path.find("/etc/NetworkManager") == 0 ||
        path.find("/etc/NetworkManager/") == 0 ||

        // Фаерволлы
        path.find("/etc/ufw") == 0 ||
        path.find("/etc/ufw/") == 0 ||

        // Политики безопасности
        path.find("/etc/security") == 0 ||
        path.find("/etc/security/") == 0 ||

        // Сертификаты SSL/TLS
        path.find("/etc/ssl/") == 0 ||
        path.find("/etc/ssl") == 0 ||
        path.find("/etc/gnutls") == 0 ||
        path.find("/etc/gnutls/") == 0 ||
        path.find("/etc/ca-certificates") == 0 ||
        path.find("/etc/ca-certificates/") == 0 ||

        // Мониторинг логов
        path.find("/etc/logcheck") == 0 ||
        path.find("/etc/logcheck/") == 0 ||

        // VPN подключения
        path.find("/etc/openvpn") == 0 ||
        path.find("/etc/openvpn/") == 0 ||

        // GUI логины
        path.find("/etc/gdm3") == 0 ||
        path.find("/etc/gdm3/") == 0 ||

        // Сетевые конфиги
        path == "/etc/hostname" ||
        path == "/etc/hosts" ||
        path == "/etc/resolv.conf" ||

        // Управление устройствами
        path.find("/etc/udev") == 0 ||
        path.find("/etc/udev/") == 0 ||

        // Управление пакетами
        path.find("/etc/dpkg") == 0;
        path.find("/etc/dpkg/") == 0;
}
bool should_skip_etc_directory(const std::string& path) {
    return !should_monitor_etc_subdir(path);
}
// --- Рекурсивное добавление слежения ---
void add_watch_recursive(int inotify_fd, const std::string& path, std::map<int, std::string>& watches) {
    std::error_code ec;

    // === Сам корень (например, /home или /etc) ставим БЕЗ фильтрации ===
    add_watch(inotify_fd, path, watches);

    for (fs::recursive_directory_iterator it(path, fs::directory_options::skip_permission_denied, ec), end;
         it != end; it.increment(ec)) {

        if (ec) {
            std::cerr << "[WARN] Ошибка обхода " << it->path() << ": " << ec.message() << std::endl;
            ec.clear();
            continue;
        }

        if (fs::is_directory(it->path())) {
            std::string subdir = it->path().string();

            if (subdir != path) {
                if (subdir.find("/home/") == 0 && should_skip_directory(subdir)) {
                    continue;
                }
                if (subdir.find("/etc/") == 0 && should_skip_etc_directory(subdir)) {
                    continue;
                }
            }

            add_watch(inotify_fd, subdir, watches);
        }
         }
}
int FileMonitoring() {
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        std::cerr << "[ERROR] inotify_init() failed\n";
        return 1;
    }

    std::map<int, std::string> watches;
    std::vector<std::string> monitor_dirs = {
        "/home",
        "/etc"
    };
    for (const auto& dir : monitor_dirs) {
        if (fs::exists(dir) && fs::is_directory(dir)) {
            add_watch_recursive(inotify_fd, dir, watches);
        } else {
            std::cerr << "[ERROR] Нет доступа или не директория: " << dir << std::endl;
        }
    }
    char buffer[4096];
    while (true) {
        int length = read(inotify_fd, buffer, sizeof(buffer));
        if (length <= 0) {
            usleep(100000);
            continue;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event* event = (struct inotify_event*)&buffer[i];

            std::string base_path = watches[event->wd];
            std::string full_path = base_path + "/" + event->name;
            fs::path path_obj(full_path);

            if (should_skip_event(full_path)) {
                i += sizeof(struct inotify_event) + event->len;
                continue;
            }

            std::string event_type;
            std::string event_name = "file";
            if (event->mask & IN_CREATE) {
                event_type = "create";
                if (event->mask & IN_ISDIR) {
                    add_watch_recursive(inotify_fd, full_path, watches);
                }
            } else if (event->mask & IN_DELETE) {
                event_type = "delete";
            } else if (event->mask & IN_MODIFY) {
                event_type = "modify";
            } else {
                event_type = "unknown";
            }


            std::string user = get_file_owner(full_path);
            std::string filename = path_obj.filename().string();

if (is_temporary_editor_file(filename)) {
    i += sizeof(struct inotify_event) + event->len;
    continue;
}

if (full_path.find("/.config/") != std::string::npos && !should_monitor_config_subdir(full_path)) {
    i += sizeof(struct inotify_event) + event->len;
    continue;
}
if (full_path.find("/etc/") == 0) {
    if (!should_monitor_etc_subdir(full_path)) {
        i += sizeof(struct inotify_event) + event->len;
        continue;
    }
}
            // // Вывод события
            // std::cout << "[" << timestamp << "] "
            //           << "[" << mac_address << "] "
            //           << "[" << event_type << "] "
            //           << "[" << user << "] "
            //           << "[" << full_path << "]"
            //           << std::endl;

            write_log("","",event_name,event_type,user,full_path);

            i += sizeof(struct inotify_event) + event->len;
        }
    }

    close(inotify_fd);
    return 0;
}