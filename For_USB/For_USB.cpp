#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <ifaddrs.h>
#include <filesystem>
#include <fstream>
#include <libud/libudev.h> // sudo apt install libudev-dev
#include "For_all.h"
#include <magic.h> // sudo apt install libmagic-dev
#include <sys/inotify.h>
#include "For_USB.h"

#include <libaudit.h>
#include <set>
#include <unordered_map>
// -a always,exit -F arch=b64 -S mount -S umount -k mount_events
// Получение метки времени в формате ISO8601


namespace fs = std::filesystem;



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
                 // write_log("","","device","ExecutableFound", "",entry.path().string());
                std::cout << LogEntry {
                    .event_name = "device",
                    .event_type = "ExecutableFound",
                    .details = entry.path().string()
                    };

            }
        }
    }
}

struct AuditEvent {
    std::string event_id;
    std::string syscall_type; // "Mounted" / "Unmounted"
    std::string username;
    std::string comm;
    std::string exe;
    std::string cwd;
    std::string dev_path;
    std::string mount_point;
    std::string timestamp;

    std::chrono::steady_clock::time_point created_at = std::chrono::steady_clock::now();

    bool isReady() const {
        return !syscall_type.empty()
            && !event_id.empty()
            && !comm.empty()
            && !exe.empty()
            && !username.empty()
            // && !dev_path.empty()
            // && !timestamp.empty()
            && !mount_point.empty()
            && (!dev_path.empty() || syscall_type == "Unmounted");
    }
};
std::set<std::string> allowed_execs = {
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/libexec/udisks2/udisksd",
    "/usr/bin/ntfs-3g"
};
void monitorAuditMountQueu() {
    std::unordered_map<std::string, AuditEvent> buffer;


    std::cout << LogEntry{
        .event_name = "app",
        .event_type = "Start",
        .details = "Monitoring mount/unmount via audit"
        };

    while (true) {
        AuditMessage msg = queue_mount.wait_and_pop();




        // ПРИШЛА СТРОКА
        std::string id = extract_event_id(msg.message);
        // Создаётся/достаётся запись с этим event_id
        // std::cout << id;
        AuditEvent& ev = buffer[id];

        if (msg.type == AUDIT_SYSCALL && !id.empty()) {

            if (ev.timestamp.empty()) {
                ev.timestamp = extract_audit_timestamp(msg.message);
            }
            if (msg.message.find("syscall=165") != std::string::npos) {
                // std::cout << id+"[debug] raw msg:\n" << msg.message << "\n";
                ev.event_id = id;

                ev.syscall_type = "Mounted";
                ev.comm = extract_syscall_comm(msg.message);
                ev.username = extract_syscall_username(msg.message);
                ev.exe = extract_syscall_exe(msg.message);
                            }
            else if (msg.message.find("syscall=166") != std::string::npos) {
                // std::cout << id+"[debug] raw msg:\n" << msg.message << "\n";
                ev.event_id = id;
                ev.syscall_type = "Unmounted";
                ev.comm = extract_syscall_comm(msg.message);
                ev.username = extract_syscall_username(msg.message);
                ev.exe = extract_syscall_exe(msg.message);
                            }

        }
        else if (msg.type == AUDIT_PATH && !id.empty()) {
            if (ev.timestamp.empty()) {
                ev.timestamp = extract_audit_timestamp(msg.message);
            }
            // std::cout << "[debug] PATH: " << msg << std::endl;
            if (msg.message.find("item=0")!= std::string::npos) {
                ev.mount_point = extract_path_path(msg.message);
                // std::cout << id +"[debug] mount_point: " << ev.mount_point << std::endl;

            }
            else if (msg.message.find("item=1")!= std::string::npos) {
                ev.dev_path = extract_path_path(msg.message);
                // std::cout << id +"[debug] from: " << ev.dev_path << std::endl;

            }
        }
        if (allowed_execs.find(ev.exe) == allowed_execs.end()) {
            buffer.erase(id); // Неинтересный процесс
            continue;
        }
        if (ev.isReady()) {
            // Выводим
            // std::cout << LogEntry{
            //     .timestamp = ev.timestamp,
            //     .event_name = "Device",
            //     .event_type = ev.syscall_type,
            //     .username = ev.username,
            //     .details = (ev.syscall_type == "Mounted")
            //         ? "Source:" + ev.dev_path + " Target:" + ev.mount_point + " Command:" + ev.comm
            //         : "From:" + ev.mount_point + " Command:" + ev.comm
            // };
            write_log_entry({
                .timestamp = ev.timestamp,
                .event_name = "Device",
                .event_type = ev.syscall_type,
                .username = ev.username,
                .details = (ev.syscall_type == "Mounted")
                    ? "Source:" + ev.dev_path + " Target:" + ev.mount_point + " Command:" + ev.comm
                    : "From:" + ev.mount_point + " Command:" + ev.comm
            });
            // std::cout << "[debug] Удаление по исполнению id=" << id << std::endl;

            buffer.erase(id);

        }
        // Удаление устаревших событий
        const auto now = std::chrono::steady_clock::now();
        const auto ttl = std::chrono::seconds(7);

        for (auto it = buffer.begin(); it != buffer.end(); ) {
            if (now - it->second.created_at > ttl) {
                // std::cout << "[debug] Удаление по TTL id=" << it->first << std::endl;
                it = buffer.erase(it);
            } else {
                ++it;
            }
        }
        }
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


    write_log_entry({.event_name = event,
        .event_type = typevent,
        .details = details.str()});
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