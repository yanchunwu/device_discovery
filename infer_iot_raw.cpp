#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ctime>
#include <thread>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
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
    std::string outputPath = "infer_iot_raw.log";
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
        << "  -o, --output <path>      Log file path (default: infer_iot_raw.log)\n"
        << "  -h, --help               Show this help message\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " eth1\n"
        << "  sudo " << prog << " -i eth1 -n 100 -t 15\n"
        << "  sudo " << prog << " -i eth1 -o capture.log\n\n"
        << "Notes:\n"
        << "  - Requires Linux.\n"
        << "  - Requires root or CAP_NET_RAW.\n"
        << "  - Best results come from starting capture, then power-cycling the IoT device.\n"
        << "  - Appends normal run output to the selected log file.\n";
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
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n\n";
                printHelp(argv[0]);
                return false;
            }
            cfg.outputPath = argv[++i];
            if (cfg.outputPath.empty()) {
                std::cerr << "Invalid output path\n\n";
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

static std::optional<std::string> getInterfaceMac(int fd, const std::string& ifname) {
    if (ifname.size() >= IFNAMSIZ) {
        return std::nullopt;
    }

    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        return std::nullopt;
    }

    return macToString(reinterpret_cast<const uint8_t*>(ifr.ifr_hwaddr.sa_data));
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

static std::optional<uint32_t> parseIpv4String(const std::string& ip) {
    struct in_addr addr {};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return ntohl(addr.s_addr);
}

static bool isUsableIpv4(const std::optional<std::string>& ip) {
    if (!ip || *ip == "unknown") {
        return false;
    }

    const auto parsed = parseIpv4String(*ip);
    return parsed && *parsed != 0;
}

static std::optional<std::string> suggestLocalTestAddress(
    const std::optional<std::string>& deviceIp,
    const std::optional<std::string>& gatewayIp) {
    const auto sourceIp = isUsableIpv4(deviceIp) ? deviceIp : gatewayIp;
    if (!sourceIp) {
        return std::nullopt;
    }

    const auto parsed = parseIpv4String(*sourceIp);
    if (!parsed) {
        return std::nullopt;
    }

    const uint32_t network = *parsed & 0xFFFFFF00u;
    uint32_t host = 10;
    if ((*parsed & 0xFFu) == host) {
        host = 11;
    }

    struct in_addr addr {};
    addr.s_addr = htonl(network | host);

    char buf[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return std::nullopt;
    }

    return std::string(buf) + "/24";
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

static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }

    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }

    return s.substr(start, end - start);
}

static std::string normalizeOuiPrefix(const std::string& value) {
    std::string normalized;
    normalized.reserve(6);

    for (const unsigned char ch : value) {
        if (std::isxdigit(ch)) {
            normalized.push_back(static_cast<char>(std::toupper(ch)));
            if (normalized.size() == 6) {
                break;
            }
        }
    }

    if (normalized.size() != 6) {
        return "";
    }

    return normalized;
}

static std::optional<std::pair<std::string, std::string>> parseOuiLine(const std::string& line) {
    const auto marker = line.find("(base 16)");
    if (marker == std::string::npos) {
        return std::nullopt;
    }

    const std::string prefix = normalizeOuiPrefix(line.substr(0, marker));
    if (prefix.empty()) {
        return std::nullopt;
    }

    const std::string vendor = trim(line.substr(marker + std::strlen("(base 16)")));
    if (vendor.empty()) {
        return std::nullopt;
    }

    return std::make_pair(prefix, vendor);
}

static std::optional<std::string> lookupMacVendor(
    const std::string& mac,
    const std::vector<std::string>& ouiPaths = {
        "/usr/share/ieee-data/oui.txt",
        "/var/lib/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
    }) {
    const std::string prefix = normalizeOuiPrefix(mac);
    if (prefix.empty()) {
        return std::nullopt;
    }

    for (const auto& path : ouiPaths) {
        std::ifstream input(path);
        if (!input) {
            continue;
        }

        std::string line;
        while (std::getline(input, line)) {
            const auto entry = parseOuiLine(line);
            if (entry && entry->first == prefix) {
                return entry->second;
            }
        }
    }

    return std::nullopt;
}

static void writeToStreams(
    const std::string& message,
    std::ostream* primary,
    std::ostream* secondary = nullptr) {
    if (primary) {
        *primary << message;
    }
    if (secondary) {
        *secondary << message;
    }
}

static std::string currentLocalTimestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm tm {};
    localtime_r(&now, &tm);

    char buf[32] = {0};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm) == 0) {
        return "unknown-time";
    }
    return buf;
}

static std::string formatRunTimestampLine(const std::string& timestamp) {
    return "Timestamp: " + timestamp + "\n";
}

static std::string formatInferenceReport(const Config& cfg, int captured, const Observation& obs) {
    const auto deviceMac = mostFrequent(obs.macCount);
    const auto deviceIp = mostFrequent(obs.srcIpCount);
    const auto gatewayIp = mostFrequent(obs.arpGatewayCount);
    const auto deviceVendor = deviceMac ? lookupMacVendor(*deviceMac) : std::nullopt;
    const auto suggestedLocalIp = suggestLocalTestAddress(deviceIp, gatewayIp);

    std::ostringstream out;
    out << "\nInference result\n";
    out << "================\n";
    out << "Captured packets: " << captured << "\n";
    out << "Likely device MAC: " << (deviceMac ? *deviceMac : "unknown") << "\n";
    if (deviceVendor) {
        out << "Likely device vendor: " << *deviceVendor << "\n";
    }
    out << "Likely device IP: " << (deviceIp ? *deviceIp : "unknown") << "\n";
    out << "Likely gateway IP: " << (gatewayIp ? *gatewayIp : "unknown") << "\n";

    if (!obs.linkLocalProbes.empty()) {
        out << "Link-local probe(s):\n";
        for (const auto& ip : obs.linkLocalProbes) {
            out << "  - " << ip << "\n";
        }
    } else {
        out << "Link-local probe(s): none seen\n";
    }

    out << "SSDP observed: " << (obs.sawSSDP ? "yes" : "no") << "\n";

    if (suggestedLocalIp) {
        out << "\nSuggested next test:\n";
        out << "  sudo ip addr flush dev " << cfg.ifname << "\n";
        out << "  sudo ip addr add " << *suggestedLocalIp << " dev " << cfg.ifname << "\n";
        out << "  sudo ip link set " << cfg.ifname << " up\n";
        if (isUsableIpv4(deviceIp)) {
            out << "  ping -I " << cfg.ifname << " " << *deviceIp << "\n";
        }
    }

    return out.str();
}

static constexpr auto kInterfacePollInterval = std::chrono::milliseconds(250);

static int interfacePollAttempts(int timeoutSec) {
    const auto timeoutMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::seconds(timeoutSec));
    return static_cast<int>(timeoutMs / kInterfacePollInterval) + 1;
}

template <typename Resolver, typename Sleeper>
static std::optional<int> waitForInterface(
    const std::string& ifname,
    int attempts,
    Resolver&& resolver,
    Sleeper&& sleeper,
    std::ostream* statusStream = nullptr,
    std::ostream* logStream = nullptr) {
    bool announcedWait = false;

    for (int attempt = 0; attempt < attempts; ++attempt) {
        const unsigned int ifindex = resolver(ifname.c_str());
        if (ifindex != 0) {
            return static_cast<int>(ifindex);
        }

        if (attempt + 1 >= attempts) {
            break;
        }

        if (statusStream && !announcedWait) {
            writeToStreams("Waiting for interface " + ifname + " to appear...\n", statusStream, logStream);
            announcedWait = true;
        }

        sleeper();
    }

    return std::nullopt;
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

#ifndef INFER_IOT_RAW_TEST
int main(int argc, char* argv[]) {
    Config cfg;
    if (!parseArgs(argc, argv, cfg)) {
        return (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) ? 0 : 1;
    }

    const std::string runTimestamp = currentLocalTimestamp();

    errno = 0;
    std::ofstream logFile(cfg.outputPath, std::ios::app);
    std::ostream* logStream = nullptr;
    if (!logFile) {
        const int logOpenErrno = errno;
        std::cerr << "Warning: failed to open log file '" << cfg.outputPath
                  << "': " << std::strerror(logOpenErrno) << "\n";
    } else {
        logStream = &logFile;
        *logStream << "=== infer_iot_raw run at " << currentLocalTimestamp() << " ===\n";
    }

    writeToStreams(formatRunTimestampLine(runTimestamp), &std::cout, logStream);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        std::cerr << "socket() failed: " << std::strerror(errno) << "\n";
        return 1;
    }

    const auto ifindex = waitForInterface(
        cfg.ifname,
        interfacePollAttempts(cfg.timeoutSec),
        [](const char* ifname) { return if_nametoindex(ifname); },
        []() { std::this_thread::sleep_for(kInterfacePollInterval); },
        &std::cout,
        logStream);
    if (!ifindex) {
        std::cerr << "Interface did not appear within timeout: " << cfg.ifname << "\n";
        close(fd);
        return 1;
    }

    const auto ownMac = getInterfaceMac(fd, cfg.ifname);
    if (!ownMac) {
        std::cerr << "Failed to read MAC address for interface: " << cfg.ifname << "\n";
        close(fd);
        return 1;
    }

    struct sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = *ifindex;

    if (bind(fd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        std::cerr << "bind() failed: " << std::strerror(errno) << "\n";
        close(fd);
        return 1;
    }

    {
        std::ostringstream status;
        status << "Listening on " << cfg.ifname
               << " for up to " << cfg.maxPackets
               << " packets or " << cfg.timeoutSec << " seconds...\n";
        writeToStreams(status.str(), &std::cout, logStream);
    }

    Observation obs;
    std::vector<uint8_t> buf(65536);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.timeoutSec);

    int captured = 0;
    while (captured < cfg.maxPackets) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            writeToStreams("Timeout reached.\n", &std::cout, logStream);
            break;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv{};
        tv.tv_sec = remaining.count() / 1000000;
        tv.tv_usec = remaining.count() % 1000000;

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
            writeToStreams("Timeout reached.\n", &std::cout, logStream);
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

        const auto* eth = reinterpret_cast<const struct ether_header*>(buf.data());
        if (macToString(eth->ether_shost) == *ownMac) {
            continue;
        }

        ++captured;

        const uint16_t etherType = ntohs(eth->ether_type);

        if (etherType == ETHERTYPE_ARP) {
            handleArp(buf.data(), n, obs);
        } else if (etherType == ETHERTYPE_IP) {
            handleIpv4(buf.data(), n, obs);
        }
    }

    close(fd);

    writeToStreams(formatInferenceReport(cfg, captured, obs), &std::cout, logStream);
    if (logStream) {
        *logStream << "\n";
        logFile.flush();
    }

    return 0;
}
#endif
