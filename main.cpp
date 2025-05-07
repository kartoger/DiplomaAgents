#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <ifaddrs.h>
#include <filesystem>
#include <fstream>
#include <libud/libudev.h> // sudo apt install libudev-dev
#include <sys/inotify.h>
#include "For_SSH_GDM/For_SSH_GDM.h"
#include "For_USB/For_USB.h"
#include "For_all.h"
#include "For_ScanUsers/For_ScanUsers.h"
#include <magic.h> // sudo apt install libmagic-dev
namespace fs = std::filesystem;





// --- main() теперь сводится только к двум вызовам ---
int main() {
    // 1) Вывести стартовое сообщение

    // write_log("","","app","Start","","Monitoring USB block devices");
    // monitorUsbDevices();
    // write_log("","","app","Start","","Monitoring mount/unmount via audit");
    // monitorAuditMount();
    // 2) Запустить мониторинг


    // write_log("","","app","Start","","Monitoring SSH GDM access");
    // ssh_gdm_monitoring();


    write_log("","","app","Start","","Monitoring Active Terminals");
    get_active_terminals_logs();
    return 0;
}
