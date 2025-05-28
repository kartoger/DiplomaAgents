#include <fstream>
#include <functional>
#include "For_all.h"
#include "For_FileSystem/FileMonitoring.h"
#include "For_USB/For_USB.h"
#include <iostream>
#include <thread>
#include <bits/fs_fwd.h>
#include <filesystem>
#include <chrono>
#include "For_SSH_GDM/For_SSH_GDM.h"
#include "For_ScanUsers/For_ScanUsers.h"
#include "For_exec_priv/Monitor_exec.h"
// --- main() теперь сводится только к двум вызовам ---
void run_periodically(std::function<void()> func, std::chrono::minutes interval) {
    std::thread([func, interval]() {
        while (true) {
            func();  // вызываем целевую функцию
            std::this_thread::sleep_for(interval);  // пауза между вызовами
        }
    }).detach();  // запускаем в фоне, не блокируя main
}


void rename_file(const std::string& old_name, const std::string& new_name, int delta_time, bool& is_critical, bool& is_running) {
    // Запоминаем текущее время
    auto start_time = std::chrono::steady_clock::now();
    while (is_running) {
        if (is_critical || std::chrono::steady_clock::now() - start_time >= std::chrono::seconds(delta_time)) {
            // Если прошло 60 секунд, переименовываем файл
            start_time = std::chrono::steady_clock::now();
            std::cout << "Переименование файла..." << std::endl;
            // Проверяем, существует ли файл
            if (std::filesystem::exists(old_name)) {
                // Проверяем, существует ли файл с новым именем
                if (std::filesystem::exists(new_name)) {
                    std::cout << "Файл с именем " << new_name << " уже существует." << std::endl;
                    continue;
                }
                // Переименовываем файл
                std::filesystem::rename(old_name, new_name);
                std::cout << "Файл переименован с " << old_name << " на " << new_name << std::endl;
                if (is_critical) {
                    std::cout << "triggered" << std::endl;
                    is_critical = false;
                }
            } else {
                std::cout << "Файл " << old_name << " не существует." << std::endl;
            }
        }
        // Ждем 1 секунду перед следующей проверкой
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}






int main() {
    int audit_fd = init_audit_socket();
    if (audit_fd < 0) return 1;

    std::string file_path = "/home/client/Desktop/log.txt";
    std::string new_file_name = "/home/client/Desktop/log-send.txt";
    // Переменная для экстренного переименования
    bool is_critical = false;
    // Переменная для завершения функции
    bool is_running = true;
    std::thread rename_thread(rename_file, file_path, new_file_name, 90, std::ref(is_critical), std::ref(is_running));
    std::ofstream outfile("/home/client/Desktop/log.txt");

    //FINAL
    //log.txt
    ///home/client/Desktop/log.txt
    ;
    run_periodically(get_active_terminals_logs, std::chrono::minutes(1));
    std::thread t1(ssh_gdm_monitoring);
    std::thread t2(audit_event_reader, audit_fd);
    // std::thread t3(monitorAuditMountQueu);
    // std::thread t4(monitorUsbDevices);
    // std::thread t5(monitor_exec_from_queu);
    // std::thread t6(FileMonitoring);

    t1.join();
    t2.join();
    // t3.join();
    // t4.join();
    // t5.join();
    // t6.join();
    // rename_thread.join();

    return 0;
}
