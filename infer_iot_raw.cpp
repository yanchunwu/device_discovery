#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

struct Observation {
    std::map<std::string, int> macCount;
    std::map<std::string, int> srcIpCount;
    std::map<std::string, int> arpGatewayCount;
    std::set<std::string> linkLocalProbes;
    bool sawSSDP = false;
};

struct Config {
    std::string ifname;
    int maxPackets = 200;
    int timeoutSec = 30;
};

static void printHelp(const char* prog) {
    std::cout
        << "Usage:\n"
        << "  " << prog << " [options] <interface>\n"
        << "  " << prog << " [options] -i <interface>\n\n"
        << "Description:\n"
        << "  Capture raw Ethernet frames on a Linux interface and infer likely\n"
        << "  IoT device network information from ARP and IPv4/UDP traffic.\n\n"
        << "Options:\n"
        << "  -i, --interface <name>   Network interface to listen on\n"
        << "  -n, --packets <count>    Maximum number of packets to capture (default: 200)\n"
        << "  -t, --timeout <sec>      Stop after timeout in seconds (default: 30)\n"
        << "  -h, --help               Show this help message\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " eth1\n"
        << "  sudo " << prog << " -i eth1 -n 100 -t 15\n\n"
        << "Notes:\n"
        << "  - Requires Linux.\n"
        << "  - Requires root or CAP_NET_RAW.\n"
        << "  - Best results come from starting capture, then power-cycling the IoT device.\n";
}

static bool parseInt(const std::string& s, int& value) {
    try {
        size_t idx = 0;
        int v = std::stoi(s, &idx);
        if (idx != s.size()) {
            return false;
        }
        value = v;
        return true;
    } catch (...) {
        return false;
    }
}

static bool parseArgs(int argc, char* argv[], Config& cfg) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printHelp(argv[0]);
            return false;
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n\n";
                printHelp(argv[0]);
                return false;
            }
            cfg.ifname = argv[++i];
        } else if (arg == "-n" || arg == "--packets") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n\n";
                printHelp(argv[0]);
                return false;
            }
            if (!parseInt(argv[++i], cfg.maxPackets) || cfg.maxPackets <= 0) {
                std::cerr << "Invalid packet count\n\n";
                printHelp(argv[0]);
                return false;
            }
        } else if (arg == "-t" || arg == "--timeout") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n\n";
                printHelp(argv[0]);
                return false;
            }
            if (!parseInt(argv[++i], cfg.timeoutSec) || cfg.timeoutSec <= 0) {
                std::cerr << "Invalid timeout\n\n";
                printHelp(argv[0]);
                return false;
            }
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n\n";
            printHelp(argv[0]);
            return false;
        } else {
            if (!cfg.ifname.empty()) {
                std::cerr << "Multiple interfaces provided\n\n";
                printHelp(argv[0]);
                return false;
            }
            cfg.ifname = arg;
        }
    }

    if (cfg.ifname.empty()) {
        std::cerr << "Interface is required\n\n";
        printHelp(argv[0]);
        return false;
    }

    return true;
}

static std::string macToString(const uint8_t* mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(2) << static_cast<int>(mac[0]) << ":"
        << std::setw(2) << static_cast<int>(mac[1]) << ":"
        << std::setw(2) << static_cast<int>(mac[2]) << ":"
        << std::setw(2) << static_cast<int>(mac[3]) << ":"
        << std::setw(2) << static_cast<int>(mac[4]) << ":"
        << std::setw(2) << static_cast<int>(mac[5]);
    return oss.str();
}

static std::string ipToString(uint32_t ip_be) {
    char buf[INET_ADDRSTRLEN] = {0};
    struct in_addr addr{};
    addr.s_addr = ip_be;
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "unknown";
    }
    return std::string(buf);
}

static bool isLinkLocal(const std::string& ip) {
    return ip.rfind("169.254.", 0) == 0;
}

static std::optional<std::string> mostFrequent(const std::map<std::string, int>& counts) {
    int best = -1;
    std::optional<std::string> value;
    for (const auto& [k, v] : counts) {
        if (v > best) {
            best = v;
            value = k;
        }
    }
    return value;
}

static void handleArp(const uint8_t* frame, ssize_t len, Observation& obs) {
    if (len < static_cast<ssize_t>(sizeof(struct ether_header) + sizeof(struct ether_arp))) {
        return;
    }

    const auto* eth = reinterpret_cast<const struct ether_header*>(frame);
    const auto* arp = reinterpret_cast<const struct ether_arp*>(frame + sizeof(struct ether_header));

    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REQUEST) {
        return;
    }

    const std::string srcMac = macToString(eth->ether_shost);
    obs.macCount[srcMac]++;

    uint32_t spa_be = 0;
    uint32_t tpa_be = 0;
    std::memcpy(&spa_be, arp->arp_spa, sizeof(spa_be));
    std::memcpy(&tpa_be, arp->arp_tpa, sizeof(tpa_be));

    const std::string tellIp = ipToString(spa_be);
    const std::string whoHas = ipToString(tpa_be);

    if (tellIp != "0.0.0.0") {
        obs.srcIpCount[tellIp]++;
    }

    if (tellIp == "0.0.0.0" && isLinkLocal(whoHas)) {
        obs.linkLocalProbes.insert(whoHas);
    } else if (tellIp != "0.0.0.0" && whoHas != tellIp) {
        obs.arpGatewayCount[whoHas]++;
    }
}

static void handleIpv4(const uint8_t* frame, ssize_t len, Observation& obs) {
    if (len < static_cast<ssize_t>(sizeof(struct ether_header) + sizeof(struct iphdr))) {
        return;
    }

    const auto* eth = reinterpret_cast<const struct ether_header*>(frame);
    const auto* ip = reinterpret_cast<const struct iphdr*>(frame + sizeof(struct ether_header));

    if (ip->version != 4) {
        return;
    }

    const size_t ipHeaderLen = static_cast<size_t>(ip->ihl) * 4;
    if (len < static_cast<ssize_t>(sizeof(struct ether_header) + ipHeaderLen)) {
        return;
    }

    const std::string srcMac = macToString(eth->ether_shost);
    const std::string srcIp = ipToString(ip->saddr);
    const std::string dstIp = ipToString(ip->daddr);

    obs.macCount[srcMac]++;
    obs.srcIpCount[srcIp]++;

    if (ip->protocol != IPPROTO_UDP) {
        return;
    }

    if (len < static_cast<ssize_t>(sizeof(struct ether_header) + ipHeaderLen + sizeof(struct udphdr))) {
        return;
    }

    const auto* udp = reinterpret_cast<const struct udphdr*>(
        frame + sizeof(struct ether_header) + ipHeaderLen);

    const uint16_t dstPort = ntohs(udp->dest);

    if (dstIp == "239.255.255.250" && dstPort == 1900) {
        obs.sawSSDP = true;
    }
}

int main(int argc, char* argv[]) {
    Config cfg;
    if (!parseArgs(argc, argv, cfg)) {
        return (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) ? 0 : 1;
    }

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        std::cerr << "socket() failed: " << std::strerror(errno) << "\n";
        return 1;
    }

    int ifindex = if_nametoindex(cfg.ifname.c_str());
    if (ifindex == 0) {
        std::cerr << "Unknown interface: " << cfg.ifname << "\n";
        close(fd);
        return 1;
    }

    struct sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        std::cerr << "bind() failed: " << std::strerror(errno) << "\n";
        close(fd);
        return 1;
    }

    std::cout << "Listening on " << cfg.ifname
              << " for up to " << cfg.maxPackets
              << " packets or " << cfg.timeoutSec << " seconds...\n";

    Observation obs;
    std::vector<uint8_t> buf(65536);

    int captured = 0;
    while (captured < cfg.maxPackets) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv{};
        tv.tv_sec = cfg.timeoutSec;
        tv.tv_usec = 0;

        int rc = select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "select() failed: " << std::strerror(errno) << "\n";
            close(fd);
            return 1;
        }
        if (rc == 0) {
            std::cout << "Timeout reached.\n";
            break;
        }

        ssize_t n = recv(fd, buf.data(), buf.size(), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "recv() failed: " << std::strerror(errno) << "\n";
            close(fd);
            return 1;
        }

        if (n < static_cast<ssize_t>(sizeof(struct ether_header))) {
            continue;
        }

        ++captured;

        const auto* eth = reinterpret_cast<const struct ether_header*>(buf.data());
        const uint16_t etherType = ntohs(eth->ether_type);

        if (etherType == ETHERTYPE_ARP) {
            handleArp(buf.data(), n, obs);
        } else if (etherType == ETHERTYPE_IP) {
            handleIpv4(buf.data(), n, obs);
        }
    }

    close(fd);

    auto deviceMac = mostFrequent(obs.macCount);
    auto deviceIp = mostFrequent(obs.srcIpCount);
    auto gatewayIp = mostFrequent(obs.arpGatewayCount);

    std::cout << "\nInference result\n";
    std::cout << "================\n";
    std::cout << "Captured packets: " << captured << "\n";
    std::cout << "Likely device MAC: " << (deviceMac ? *deviceMac : "unknown") << "\n";
    std::cout << "Likely device IP: " << (deviceIp ? *deviceIp : "unknown") << "\n";
    std::cout << "Likely gateway IP: " << (gatewayIp ? *gatewayIp : "unknown") << "\n";

    if (!obs.linkLocalProbes.empty()) {
        std::cout << "Link-local probe(s):\n";
        for (const auto& ip : obs.linkLocalProbes) {
            std::cout << "  - " << ip << "\n";
        }
    } else {
        std::cout << "Link-local probe(s): none seen\n";
    }

    std::cout << "SSDP observed: " << (obs.sawSSDP ? "yes" : "no") << "\n";

    if (deviceIp) {
        std::cout << "\nSuggested next test:\n";
        std::cout << "  sudo ip addr flush dev " << cfg.ifname << "\n";
        std::cout << "  sudo ip addr add 172.19.0.10/16 dev " << cfg.ifname << "\n";
        std::cout << "  sudo ip link set " << cfg.ifname << " up\n";
        std::cout << "  ping -I " << cfg.ifname << " " << *deviceIp << "\n";
    }

    return 0;
}
