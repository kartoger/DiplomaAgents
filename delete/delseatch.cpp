#include <iostream>
#include <cstdlib>
#include <thread>
#include <chrono>

int main() {
    while (true) {
        std::system("clear");
        std::cout << "Последние события по ключу watch_delete_dir:\n" << std::endl;
        std::system("ausearch -k watch_delete_dir --start recent | grep 'nametype=DELETE'");
	std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return 0;
}
