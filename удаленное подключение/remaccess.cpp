#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <dirent.h>
#include <vector>
#include <algorithm>


std::vector<std::string> suspicious_apps = {
    "anydesk", "teamviewer", "rustdesk", "dwservice", "chrome-remote-desktop"
};

bool is_suspicious(const std::string& cmdline) {
    for (const auto& app : suspicious_apps) {
        if (cmdline.find(app) != std::string::npos)
            return true;
    }
    return false;
}

void check_processes() {
    DIR* proc = opendir("/proc");
    if (!proc) return;

    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        std::string pid_str(entry->d_name);
        if (!std::all_of(pid_str.begin(), pid_str.end(), ::isdigit)) continue;

        std::string cmdline_path = "/proc/" + pid_str + "/cmdline";
        std::ifstream cmdfile(cmdline_path);
        if (!cmdfile.is_open()) continue;

        std::string cmdline;
        std::getline(cmdfile, cmdline);
        cmdfile.close();

        if (is_suspicious(cmdline)) {
            std::cout << "[ALERT] Suspicious remote access detected: " << cmdline << "\n";
            std::ofstream log("/var/log/remote_monitor.log", std::ios::app);
            log << "[ALERT] PID " << pid_str << ": " << cmdline << std::endl;
            log.close();
        }
    }

    closedir(proc);
}

int main() {
    daemon(0, 0); // делаем фоновым процессом

    while (true) {
        check_processes();
        sleep(10); // каждые 10 секунд
    }

    return 0;
}
