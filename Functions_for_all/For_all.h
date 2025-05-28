#pragma once

#include <string>
#include <ostream>
#include <unistd.h>    // для getlogin()
#include <unordered_map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstring>

int init_audit_socket();
std::string extract_syscall_num(const std::string& msg);
std::string extract_exec_argc(const std::string& msg);
std::string extract_cwd_path(const std::string& msg);
std::string extract_audit_timestamp(const std::string& msg);
std::string extract_syscall_exe(const std::string& msg);
std::string extract_syscall_comm(const std::string& msg);
std::string extract_syscall_username(const std::string& msg);
std::string extract_event_id(const std::string& msg);
std::string extractPath_mount(const std::string& msg);
std::string extract_path_path(const std::string& msg);
void handleCwdPath(const std::string& msg, std::unordered_map<int, std::string>& pidToUnmountPath);
int extract_ppid(const std::string& msg);
int extract_pid(const std::string& msg);
// Получить текущее время в ISO-формате UTC
std::string getTimestamp();

// Прочитать MAC-адрес из /sys/class/net/... или вернуть 00:...
std::string getMacAddress();

std::string convertTimestampToISO8601(const std::string& timestampStr);
// Сам LogEntry — только объявление
struct LogEntry {
    std::string timestamp    = getTimestamp();
    std::string mac          = getMacAddress();
    std::string event_name   = "none";
    std::string event_type   = "none";
    std::string username     = getlogin();
    std::string details      = "none";


    // Перегрузка вывода в ostream
    friend std::ostream& operator<<(std::ostream& os, const LogEntry& e);
};
void audit_event_reader(int audit_fd);
template <typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue;
    mutable std::mutex mtx;
    std::condition_variable cv;

public:
    void push(const T& value) {
        std::lock_guard<std::mutex> lock(mtx);
        queue.push(value);
        cv.notify_one();
    }

    T wait_and_pop() {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [this]() { return !queue.empty(); });
        T value = queue.front();
        queue.pop();
        return value;
    }

    bool try_pop(T& value) {
        std::lock_guard<std::mutex> lock(mtx);
        if (queue.empty()) return false;
        value = queue.front();
        queue.pop();
        return true;
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mtx);
        return queue.empty();
    }
};
struct AuditMessage {
    int type;
    std::string message;
};
// extern ThreadSafeQueue<AuditMessage> audit_event_queue;
extern ThreadSafeQueue<AuditMessage> queue_mount;
extern ThreadSafeQueue<AuditMessage> queue_exec;
// Декларация write_log с default-параметрами
// (default-аргументы указываем ТОЛЬКО здесь)

void debug_audit_reader(int audit_fd);
void write_log(std::string timestamp   = "",
               std::string mac         = "",
               std::string event_name  = "none",
               std::string event_type  = "none",
               std::string username    = "",
               std::string details     = "none");
void write_log_entry(const LogEntry& e);