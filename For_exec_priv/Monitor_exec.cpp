#include <iostream>
#include "Monitor_exec.h"
#include <For_all.h>
#include <regex>
#include <pwd.h>
#include <libaudit.h>

#include <unordered_map>


struct ExecEventGroup {
    std::string exec_path;
    std::string cwd_path;
    std::string full_comand;
    std::string timestamp;
    std::string username;

};


void monitor_exec_from_queu() {
    std::cout << LogEntry{
        .event_name = "app",
        .event_type = "Start",
        .details = "Monitoring execve events (from queue)"
    };

    std::unordered_map<std::string, ExecEventGroup> event_groups;

    while (true) {

        AuditMessage msg = queue_exec.wait_and_pop();
        const std::string& line = msg.message;

        // Только типы, связанные с exec
        if (msg.type != AUDIT_SYSCALL &&
            msg.type != AUDIT_CWD &&
            msg.type != AUDIT_EXECVE &&
            msg.type != AUDIT_PROCTITLE)
            continue;

        std::string event_id = extract_event_id(line);
        if (event_id.empty()) continue;

        ExecEventGroup& group = event_groups[event_id];

        if (msg.type == AUDIT_SYSCALL) {
            group.exec_path = extract_syscall_exe(line);
            group.username  = extract_syscall_username(line);
            group.timestamp = extract_audit_timestamp(line);
        }
        else if (msg.type == AUDIT_CWD) {
            group.cwd_path = extract_cwd_path(line);
        }
        else if (msg.type == AUDIT_EXECVE) {
            group.full_comand = extract_exec_argc(line);
        }

        if (!group.exec_path.empty() &&
            !group.cwd_path.empty() &&
            !group.full_comand.empty() &&
            !group.timestamp.empty()) {

            write_log_entry({
                .timestamp   = group.timestamp,
                .event_name  = "Terminal",
                .event_type  = "execve",
                .username    = group.username,
                .details     = "cwd_path=" + group.cwd_path +
                               ", exec_path=" + group.exec_path +
                               ", full_comand=" + group.full_comand
            });

            event_groups.erase(event_id);  // удаляем использованное событие
            }
    }
}