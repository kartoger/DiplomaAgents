#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <ifaddrs.h>
#include <filesystem>
#include <netpacket/packet.h>
#include <fstream>
#include <libud/libudev.h> // sudo apt install libudev-dev
#include <sys/inotify.h>
#include "For_SSH_GDM/For_SSH_GDM.h"
#include <magic.h> // sudo apt install libmagic-dev
namespace fs = std::filesystem;

// -a always,exit -F arch=b64 -S mount -S umount -k mount_events
// Получение метки времени в формате ISO8601
std::string getTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%FT%TZ");
    return ss.str();
}

// Чтение MAC-адреса из sysfs
std::string getMacAddress() {
    std::ifstream file("/sys/class/net/enp3s0/address");
    std::string mac;
    if (file.is_open()) {
        std::getline(file, mac);
    } else {
        mac = "00:00:00:00:00:00";
    }
    return mac;
}

// Универсальная функция вывода логов
// void write_log(const std::string& action, const std::string& details) {

void write_log(std::string timestamp = "none",
                  std::string mac = "none",
                  std::string event_name = "none" ,
                  std::string event_type = "none",
                  std::string username = "",
                  std::string details = "none") {
    if (timestamp == "") {
        timestamp = getTimestamp();
    }
    if (mac == "") {
        mac = getMacAddress();
    }
    if (username == "") {
        username = getlogin();
    }
    std::cout << "[" << timestamp    << "] "
              << "[" << mac   << "] "
              << "[" << event_name << "::" << event_type    << "] "
              << "[" << username << "] "
              << "[" << details           << "]\n";



    // const char* user = getlogin();
    // std::cout << "[" << timestamp    << "] "
    //           << "[" << mac   << "] "
    //           << "[" << event_name         << "] "
    //           << "[" << (user? user:"unknown") << "] "
    //           << "[" << details           << "]\n";
}



// Вспомогалка: вырезает значение между start и end
std::string extractValue(const std::string& str, const std::string& start, const std::string& end) {
    size_t p = str.find(start);
    if (p == std::string::npos) return "";
    p += start.size();
    size_t q = str.find(end, p);
    if (q == std::string::npos) return "";
    return str.substr(p, q-p);
}


bool isExecutableFile(const fs::path& filePath) {
    // 1. Проверка прав на исполнение
    std::error_code ec;
    auto perms = fs::status(filePath, ec).permissions();
    bool hasExecBit = !ec && (perms & fs::perms::owner_exec) != fs::perms::none;

    // 2. Чтение магии (ELF или #!)
    std::ifstream f(filePath, std::ios::binary);
    char magic[4] = {0};
    f.read(magic, 4);
    bool isElf = magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
    bool isScript = magic[0] == '#' && magic[1] == '!';

    // 3. magic(3) — использование libmagic
    magic_t magicCookie = magic_open(MAGIC_NONE);
    if (!magicCookie || magic_load(magicCookie, nullptr) != 0) {
        magic_close(magicCookie);
        return (hasExecBit && (isElf || isScript)); // fallback
    }


    const char* result = magic_file(magicCookie, filePath.c_str());
    std::string type = result ? result : "";
    magic_close(magicCookie);

    bool isMagicExec =
        type.find("executable") != std::string::npos ||
        type.find("script") != std::string::npos;

    return (hasExecBit && (isElf || isScript || isMagicExec));
}

void scanForExecutables(const std::string& path) {
    for (const auto& entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied)) {
        if (fs::is_regular_file(entry.path())) {
            if (isExecutableFile(entry.path())) {
                 // write_log("device::ExecutableFound", entry.path().string());
                write_log("","","device::","ExecutableFound","",entry.path().string());
            }
        }
    }
}
// Основная функция-монитор: следит за /var/log/audit/audit.log через inotify,
// парсит только записи с key="mount_events" и выводит device::Mounted/Unmounted
void monitorAuditMount() {
    const std::string AUDIT_LOG   = "/var/log/audit/audit.log";
    std::string mountSource;
    std::string mountTarget;
    int in_fd = inotify_init();
    if (in_fd < 0) {
        perror("inotify_init");
        return;
    }

    int wd = inotify_add_watch(in_fd, AUDIT_LOG.c_str(), IN_MODIFY);
    if (wd < 0) {
        perror("inotify_add_watch");
        close(in_fd);
        return;
    }

    std::ifstream auditFile(AUDIT_LOG);
    if (!auditFile.is_open()) {
        std::cerr << "Cannot open " << AUDIT_LOG << "\n";
        close(in_fd);
        return;
    }

    auditFile.seekg(0, std::ios::end);
    char buf[4096];

    std::string currentEventId;
    std::string action;
    std::string eventName = "device";
    bool waitingForPath = false;

    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(in_fd, &fds);

        if (select(in_fd+1, &fds, nullptr, nullptr, nullptr) > 0) {
            read(in_fd, buf, sizeof(buf)); // сброс уведомления inotify
            // std::cout << "inotify triggered\n";

            auditFile.clear(); // сброс EOF
            std::string line;

            while (std::getline(auditFile, line)) {
                // Отладка: покажем все строки
                // std::cout << "[debug] LINE: " << line << "\n";



// std::string syscallRaw = extractValue(line, "syscall=", " ");
//                 int syscallNum = -1;
//                 try {
//                     syscallNum = std::stoi(syscallRaw);
//                 } catch (const std::invalid_argument&) {
//                     std::cerr << "[debug] Could not parse syscall from line: " << line << "\n";
//                     continue;
//                 }

//
// if (syscallNum == 165) {
//     action = "device::Mounted";
// } else if (syscallNum == 166) {
//     action = "device::Unmounted";
// }
                // bool isMount = (syscallNum == 165);
                // bool isUmount = (syscallNum == 166);




                // Ищем строку SYSCALL с mount или umount
                bool isMount = (line.find("type=SYSCALL") != std::string::npos &&
                                (line.find("comm=\"mount") != std::string::npos) || ((line.find("comm=\"pool-udisksd") != std::string::npos) && (line.find("syscall=165") != std::string::npos)));
                bool isUmount = (line.find("type=SYSCALL") != std::string::npos &&
                                 (line.find("comm=\"umount") != std::string::npos) || ((line.find("comm=\"pool-udisksd") != std::string::npos) && (line.find("syscall=166") != std::string::npos)));
                if (isMount || isUmount) {
                    std::string header = extractValue(line, "audit(", ")");
                    if (header.empty()) continue;
                     // std::cout << "[debug] LINE: " << line << "\n";
                    auto pos = header.find(':');
                    if (pos == std::string::npos) continue;

                    currentEventId = header.substr(pos + 1);
                    action = (isMount ? "Mounted" : "Unmounted");
                    waitingForPath = true;
                    // std::cout << "[debug] SYSCALL MATCH: " << action << ", eventId=" << currentEventId << "\n";
                    continue;
                }

                // Если ждём PATH-сообщение с тем же event_id
                if (waitingForPath &&
                    line.find("type=PATH") != std::string::npos &&
                    line.find(currentEventId) != std::string::npos) {

                    std::string devPath = extractValue(line, "name=\"", "\"");
                     // std::cout << devPath << " **********\n";
                    // std::cout << action << "\n";

                    if (!devPath.empty()) {
                        if (action == "Mounted") {
                            if (devPath.find("/dev/") == 0) {
                                mountSource = devPath;
                            } else {
                                mountTarget = devPath;
                            }


                            if (!mountSource.empty() && !mountTarget.empty()) {
                                write_log("","",eventName,action,"", "Source:" + mountSource + " " + "Target:"+mountTarget);
                                waitingForPath = false;
                                currentEventId.clear();
                                scanForExecutables(mountTarget);
                                mountSource.clear();
                                mountTarget.clear();
                            }
                        } else if (action == "Unmounted") {
                            // write_log(action, "From:"+devPath);
                            write_log("","",eventName,action,"", "From:"+devPath);
                            waitingForPath = false;
                            currentEventId.clear();
                        }
                    }
                }
            }
        }
    }

    inotify_rm_watch(in_fd, wd);
    close(in_fd);
}




void handleDeviceEvent(struct udev_device* dev) {
    const char* action = udev_device_get_action(dev);
    std::string event = "device";
    std::string typevent = "unknown";
    // Проверяем, что родительское устройство — USB
    struct udev_device* usb_dev =
        udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_device");
    if (!usb_dev)
        return;

    // Путь-нод, VID/PID
    const char* devnode = udev_device_get_devnode(dev);
    const char* vid     = udev_device_get_sysattr_value(usb_dev, "idVendor");
    const char* pid     = udev_device_get_sysattr_value(usb_dev, "idProduct");


    // if (!action || std::strcmp(action, "add") != 0)
    //     return;
    if (action && std::strcmp(action, "add")==0) {
        // обработать включение
        typevent = "Add_USB";
    }
    if (action && std::strcmp(action, "remove")==0) {
        // обработать отключение
        typevent = "Remove_USB";
    }


    std::ostringstream details;
    details << (devnode ? devnode : "unknown");
    if (vid && pid) {
        details << " (VID:PID=" << vid << ":" << pid << ")";
    }
    std::string final_log = event + typevent;
    // write_log(final_log, details.str());
    write_log("","",event,typevent,"",details.str());
}

// Функция-монитор: инициализирует udev, вешает фильтр, входит в бесконечный цикл,
// и при каждом событии вызывает handleDeviceEvent()
void monitorUsbDevices() {
    struct udev* udev = udev_new();
    if (!udev) {
        std::cerr << "Can't create udev\n";
        return;
    }

    struct udev_monitor* mon = udev_monitor_new_from_netlink(udev, "udev");
    udev_monitor_filter_add_match_subsystem_devtype(mon, "block", "disk");
    udev_monitor_enable_receiving(mon);
    int fd = udev_monitor_get_fd(mon);

    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        if (select(fd+1, &fds, nullptr, nullptr, nullptr) > 0
            && FD_ISSET(fd, &fds)) {
            if (auto dev = udev_monitor_receive_device(mon)) {
                handleDeviceEvent(dev);
                udev_device_unref(dev);
            }
        }
    }

    udev_unref(udev);
}

// --- main() теперь сводится только к двум вызовам ---
int main() {
    // 1) Вывести стартовое сообщение

    // write_log("","","app","Start","","Monitoring USB block devices");
    // monitorUsbDevices();
    // write_log("","","app","Start","","Monitoring mount/unmount via audit");
    // monitorAuditMount();
    // 2) Запустить мониторинг


    write_log("","","app","Start","","Monitoring SSH GDM access");
    ssh_gdm_monitoring();
    return 0;
}
