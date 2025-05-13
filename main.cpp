
#include "For_FileSystem/FileMonitoring.h"
#include "For_USB/For_USB.h"
#include "For_all.h"
#include <iostream>
#include "For_SSH_GDM/For_SSH_GDM.h"
#include "For_ScanUsers/For_ScanUsers.h"
#include "For_exec_priv/Monitor_exec.h"
// --- main() теперь сводится только к двум вызовам ---
int main() {
    // 1) Вывести стартовое сообщение

    // write_log("","","app","Start","","Monitoring USB block devices");
    // std::cout << LogEntry{
    //     .event_name = "app",
    //     .event_type = "Start",
    //     .details = "Monitoring USB block devices"
    //     };


    //  monitorUsbDevices();
    // // write_log("","","app","Start","","Monitoring mount/unmount via audit");
    // std::cout << LogEntry{
    //     .event_name = "app",
    //     .event_type = "Start",
    //     .details = "Monitoring mount/unmount via audit"
    //     };
    // monitorAuditMount();
    // 2) Запустить мониторинг


    // write_log("","","app","Start","","Monitoring SSH GDM access");
    // std::cout << LogEntry{
    //     .event_name = "app",
    //     .event_type = "Start",
    //     .details = "Monitoring SSH GDM access"
    //     };
    // ssh_gdm_monitoring();


    // write_log("","","app","Start","","Monitoring Active Terminals");
    // get_active_terminals_logs();
    std::cout << "FSADDSDSDSDS";
    std::cout << LogEntry{
        .event_name = "app",
        .event_type = "Start",
        .details = "Monitoring Active Terminals"
        };
    // get_active_terminals_logs();

    // FileMonitoring();
    monitor_exec();
    return 0;
}
