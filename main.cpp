#include <iostream>
#include <sys/inotify.h>
#include <unistd.h>

int main() {
    int fd = inotify_init();  // создаём inotify-инстанс
    int wd = inotify_add_watch(fd, "/var/log", IN_DELETE | IN_MODIFY); // следим за логами

    char buffer[1024];
    while (true) {
        int length = read(fd, buffer, sizeof(buffer));
        if (length < 0) break;

        struct inotify_event *event = (struct inotify_event*) &buffer[0];
        if (event->len) {
            if (event->mask & IN_DELETE)
                std::cout << "Файл удалён: " << event->name << std::endl;
            else if (event->mask & IN_MODIFY)
                std::cout << "Файл изменён: " << event->name << std::endl;
        }
    }

    close(fd);
    return 0;
}
