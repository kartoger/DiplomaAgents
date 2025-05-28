#include <iostream>
#include <filesystem>
#include <fstream>
#include "For_all.h"
#include "FileMonitoring.h"
#include <libaudit.h>
#include <vector>
#include <algorithm>
struct ExecEventGroup {
    std::string exec_path;
    std::string first_path;   // путь из item=0
    std::string cwd_path;
    std::string file_name;  // имя из item=1
    std::string timestamp;
    std::string username;
    std::string syscall;
    std::string final_path;
    std::string item0;
    std::string item1;
    std::string item2;
    std::string item3;

};
bool is_temp_editor_file(const std::string& filename) {
    return filename.ends_with(".swp") || filename.ends_with(".tmp") ||
           filename.ends_with("~")     || filename.ends_with(".bak");
}
bool is_user_visible_command(const std::string& exe_path) {
    static const std::vector<std::string> whitelist = {
        // Создание
        "/usr/bin/touch", "/usr/bin/make", "/usr/bin/gcc", "/usr/bin/g++",

        // Удаление/копирование
        "/usr/bin/rm", "/usr/bin/mv", "/usr/bin/cp",

        // Редактирование
        // "/usr/bin/nano", "/usr/bin/vim", "/usr/bin/gedit",
        // "/usr/bin/kate", "/usr/bin/code", "/usr/bin/subl", "/usr/bin/leafpad",

        // Просмотр
        "/usr/bin/less", "/usr/bin/cat", "/usr/bin/xdg-open",
        "/usr/bin/evince", "/usr/bin/okular", "/usr/bin/file-roller"
    };
    return std::find(whitelist.begin(), whitelist.end(), exe_path) != whitelist.end();
}
void FileMonitoring() {
    std::cout << LogEntry{
        .event_name = "app",
        .event_type = "Start",
        .details = "Monitoring File-eventser (from queue)"
    };

    std::unordered_map<std::string, ExecEventGroup> event_groups;

    while (true) {

        AuditMessage msg = queue_exec.wait_and_pop();

        const std::string& line = msg.message;
        std::string syscall_num;
        // Только типы, связанные с exec
        if (msg.type != AUDIT_SYSCALL &&
            msg.type != AUDIT_CWD &&
            msg.type != AUDIT_EXECVE &&
            msg.type != AUDIT_PATH &&
            msg.type != AUDIT_PROCTITLE)
            continue;


        // std::cout << "|line|"<< line << std::endl;

        std::string event_id = extract_event_id(line);
        if (event_id.empty()) continue;

        ExecEventGroup& group = event_groups[event_id];

        if (msg.type == AUDIT_SYSCALL) {

            std::string comm = extract_syscall_comm(msg.message);

            std::cout << "|SYSCALL| " << msg.message << std::endl;

            group.syscall = extract_syscall_num(msg.message);
            group.exec_path = extract_syscall_exe(line);
            std::cout << "|DEBUG| |EXE| " << group.exec_path << std::endl;
            group.username  = extract_syscall_username(line);
            // std::cout << "|DEBUG| |USER| " << group.username << std::endl;
            group.timestamp = extract_audit_timestamp(line);
            // std::cout << "|DEBUG| |TIME| " << group.timestamp << std::endl;
            if (group.syscall == "316" || group.syscall == "264" || group.syscall == "82") {
                group.syscall = "rename";
            }
            else if (group.syscall == "263" || group.syscall == "87") {
                group.syscall = "delete";
                if (group.exec_path == "/usr/bin/nano") {
                }
            }
        }

        else if (msg.type == AUDIT_CWD) {
            std::cout << "|CWD|" << msg.message << std::endl;
            // std::cout << msg.message << std::endl;
            if (group.exec_path == "/usr/bin/nano") {
                group.cwd_path=extract_cwd_path(msg.message);
                std::cout << group.first_path << std::endl;
            }
        }
        else if (msg.type == AUDIT_PATH) {
            std::cout << "|PATH| " << msg.message << std::endl;
            if (group.syscall == "delete") {
                if (msg.message.find("item=0") != std::string::npos) {
                    group.first_path = extract_path_path(msg.message);
                    if (!group.first_path.empty() && group.first_path.back() != '/')
                        group.first_path += '/';
                } else if (msg.message.find("item=1") != std::string::npos) {
                    group.file_name = extract_path_path(msg.message);
                    if (group.exec_path == "/usr/bin/nano") {
                        if (group.file_name.starts_with("./.")) {
                            group.file_name = "/" + group.file_name.substr(3);  // удаляем "./.", добавляем /
                        }
                        if (group.file_name.ends_with(".swp")) {
                            group.file_name = group.file_name.substr(0, group.file_name.size() - 4); // удаляем .swp
                        }
                    }
                }

                // только когда оба компонента получены
                if (group.exec_path == "/usr/bin/nano" &&
                    !group.first_path.empty() &&
                    !group.file_name.empty()) {

                    group.file_name = group.cwd_path + group.file_name;
                    group.first_path = " ";
                    std::cout << "final path: " << group.file_name<< std::endl;
                    group.syscall = "modify";
                    }
            }
            else if (group.syscall == "rename") {
                if (msg.message.find("item=0") != std::string::npos) {
                    group.item0 = extract_path_path(msg.message);
                } else if (msg.message.find("item=1") != std::string::npos) {
                    group.item1 = extract_path_path(msg.message);
                } else if (msg.message.find("item=2") != std::string::npos) {
                    group.item2 = extract_path_path(msg.message);
                } else if (msg.message.find("item=3") != std::string::npos) {
                    group.item3 = extract_path_path(msg.message);
                }
            }
            ;
            }


        // std::cout << "|DEBUG| |PATH| " << group.file << std::endl;



        if (!group.item0.empty() && !group.item1.empty()) {
            group.first_path = group.item0 +"/"+ group.item2;
        }
        if (!group.item2.empty() && !group.item3.empty()) {
            group.file_name = ", renamed:" + group.item1 +"/"+ group.item3;
        }

        if (is_temp_editor_file(group.file_name))
            continue; // игнорируем
        if (!group.exec_path.empty() &&
            !group.timestamp.empty() &&
            !group.username.empty() &&
            !group.first_path.empty() &&
            !group.file_name.empty())
            // is_user_visible_command(group.exec_path))
            {

            if (!group.first_path.empty() && group.first_path[0] == ' ') {
                group.first_path.erase(0, 1);
            }
            write_log_entry({
                .timestamp   = group.timestamp,
                .event_name  = "File",
                .event_type  = group.syscall,
                .username    = group.username,
                .details     =
                               "exec:" + group.exec_path +
                               ", file:" + (group.first_path +group.file_name)

            });

            event_groups.erase(event_id);  // удаляем использованное событие
            }
    }
}
