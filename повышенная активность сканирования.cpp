#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <unordered_map>
#include <ctime>

#define THRESHOLD 50 // Порог пакетов за интервал
#define INTERVAL 10  // Интервал в секундах

struct Activity {
    int count;
    time_t start;
};

std::unordered_map<std::string, Activity> activity_map;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_hdr = (struct ip*)(packet + 14); // 14 байт - Ethernet header

    std::string src_ip = inet_ntoa(ip_hdr->ip_src);
    time_t now = time(nullptr);

    if (ip_hdr->ip_p == IPPROTO_ICMP || ip_hdr->ip_p == IPPROTO_TCP) {
        auto &entry = activity_map[src_ip];

        if (entry.start == 0) {
            entry.start = now;
            entry.count = 1;
        } else {
            entry.count++;
            if (now - entry.start <= INTERVAL && entry.count >= THRESHOLD) {
                std::cout << "Подозрительная активность от: " << src_ip << " (" << entry.count << " пакетов за " << INTERVAL << " секунд)" << std::endl;
                entry.start = now;
                entry.count = 0;
            } else if (now - entry.start > INTERVAL) {
                entry.start = now;
                entry.count = 1;
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        std::cerr << "Ошибка: " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(handle, 0, packet_handler, nullptr) < 0) {
        std::cerr << "pcap_loop error: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    pcap_close(handle);
    return 0;
}
