#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
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
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ctime>
#include <limits>
#include <thread>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

struct Observation {
    std::map<std::string, int> macCount;
    std::map<std::string, int> srcIpCount;
    std::map<std::string, int> arpGatewayCount;
    std::set<std::string> linkLocalProbes;
    bool sawSSDP = false;
};

struct CidrRange {
    uint32_t network = 0;
    uint32_t first = 0;
    uint32_t last = 0;
    int prefix = 0;
    std::uint64_t addressCount = 0;
};

struct Config {
    std::string ifname;
    int maxPackets = 200;
    int timeoutSec = 30;
    std::string outputPath = "infer_iot_raw.log";
    std::uintmax_t rotateBytes = 0;
    int retainCount = 5;
    std::optional<CidrRange> probeCidr;
    bool loopForever = false;
    bool quiet = false;
};

static constexpr std::uint64_t kMaxArpProbeAddresses = 65536;

static bool parseInt(const std::string& s, int& value);

static std::optional<uint32_t> parseIpv4String(const std::string& ip) {
    struct in_addr addr {};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return ntohl(addr.s_addr);
}

static std::string ipv4HostToString(uint32_t ip) {
    char buf[INET_ADDRSTRLEN] = {0};
    struct in_addr addr {};
    addr.s_addr = htonl(ip);
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
        return "unknown";
    }
    return std::string(buf);
}

static uint32_t prefixMask(int prefix) {
    if (prefix <= 0) {
        return 0;
    }
    if (prefix >= 32) {
        return 0xFFFFFFFFu;
    }
    return 0xFFFFFFFFu << (32 - prefix);
}

static std::optional<CidrRange> parseCidr(const std::string& cidr) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= cidr.size()) {
        return std::nullopt;
    }

    const auto ip = parseIpv4String(cidr.substr(0, slash));
    if (!ip) {
        return std::nullopt;
    }

    int prefix = 0;
    if (!parseInt(cidr.substr(slash + 1), prefix) || prefix < 0 || prefix > 32) {
        return std::nullopt;
    }

    const uint32_t mask = prefixMask(prefix);
    const uint32_t network = *ip & mask;
    const uint32_t broadcast = network | ~mask;

    CidrRange range;
    range.network = network;
    range.prefix = prefix;

    if (prefix <= 30) {
        range.first = network + 1;
        range.last = broadcast - 1;
    } else {
        range.first = network;
        range.last = broadcast;
    }

    range.addressCount =
        static_cast<std::uint64_t>(range.last) - static_cast<std::uint64_t>(range.first) + 1;
    return range;
}

static std::string formatCidrRange(const CidrRange& range) {
    return ipv4HostToString(range.network) + "/" + std::to_string(range.prefix);
}

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
        << "      --probe-cidr <cidr>  Actively ARP-probe a CIDR before passive capture\n"
        << "      --rotate-size <size> Rotate the log when it would exceed this size; 0 disables rotation\n"
        << "      --retain <count>     Number of rotated log files to keep (default: 5)\n"
        << "  -l, --loop               Repeat capture sessions forever\n"
        << "  -q, --quiet              Suppress normal console output; log output is unchanged\n"
        << "  -h, --help               Show this help message\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " eth1\n"
        << "  sudo " << prog << " -i eth1 -n 100 -t 15\n"
        << "  sudo " << prog << " -i eth1 --probe-cidr 192.168.11.0/24\n"
        << "  sudo " << prog << " -i eth1 -o capture.log\n"
        << "  sudo " << prog << " -i eth1 -o capture.log --rotate-size 10M --retain 7\n"
        << "  sudo " << prog << " -i eth1 --loop\n"
        << "  sudo " << prog << " -i eth1 --loop --quiet\n\n"
        << "Notes:\n"
        << "  - Requires Linux.\n"
        << "  - Requires root or CAP_NET_RAW.\n"
        << "  - Best results come from starting capture, then power-cycling the IoT device.\n"
        << "  - Use --probe-cidr to find quiet fixed-IP devices that answer ARP.\n"
        << "  - ARP probing is limited to " << kMaxArpProbeAddresses << " candidate addresses per run.\n"
        << "  - Host-originated outgoing frames and the capture NIC's own IPv4 traffic are ignored.\n"
        << "  - If a USB Ethernet interface briefly disappears, capture waits and rebinds.\n"
        << "  - Appends normal run output to the selected log file.\n"
        << "  - Rotation uses suffixes like .1, .2, and supports K, M, G, or T size suffixes.\n"
        << "  - Loop mode reruns capture sessions until interrupted.\n";
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

static bool parseByteSize(const std::string& s, std::uintmax_t& value) {
    if (s.empty()) {
        return false;
    }

    size_t idx = 0;
    while (idx < s.size() && std::isdigit(static_cast<unsigned char>(s[idx]))) {
        ++idx;
    }
    if (idx == 0) {
        return false;
    }

    unsigned long long base = 0;
    try {
        base = std::stoull(s.substr(0, idx));
    } catch (...) {
        return false;
    }

    std::string suffix = s.substr(idx);
    for (char& ch : suffix) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }

    std::uintmax_t multiplier = 1;
    if (suffix.empty() || suffix == "B") {
        multiplier = 1;
    } else if (suffix == "K" || suffix == "KB") {
        multiplier = 1024ull;
    } else if (suffix == "M" || suffix == "MB") {
        multiplier = 1024ull * 1024ull;
    } else if (suffix == "G" || suffix == "GB") {
        multiplier = 1024ull * 1024ull * 1024ull;
    } else if (suffix == "T" || suffix == "TB") {
        multiplier = 1024ull * 1024ull * 1024ull * 1024ull;
    } else {
        return false;
    }

    if (base > std::numeric_limits<std::uintmax_t>::max() / multiplier) {
        return false;
    }

    value = static_cast<std::uintmax_t>(base) * multiplier;
    return true;
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
        } else if (arg == "--probe-cidr") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n\n";
                printHelp(argv[0]);
                return false;
            }
            const std::string cidr = argv[++i];
            const auto parsed = parseCidr(cidr);
            if (!parsed) {
                std::cerr << "Invalid probe CIDR\n\n";
                printHelp(argv[0]);
                return false;
            }
            if (parsed->addressCount > kMaxArpProbeAddresses) {
                std::cerr << "Probe CIDR is too large; maximum is "
                          << kMaxArpProbeAddresses << " candidate addresses\n\n";
                printHelp(argv[0]);
                return false;
            }
            cfg.probeCidr = parsed;
        } else if (arg == "--rotate-size") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n\n";
                printHelp(argv[0]);
                return false;
            }
            if (!parseByteSize(argv[++i], cfg.rotateBytes)) {
                std::cerr << "Invalid rotate size\n\n";
                printHelp(argv[0]);
                return false;
            }
        } else if (arg == "--retain") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << "\n\n";
                printHelp(argv[0]);
                return false;
            }
            if (!parseInt(argv[++i], cfg.retainCount) || cfg.retainCount < 0) {
                std::cerr << "Invalid retain count\n\n";
                printHelp(argv[0]);
                return false;
            }
        } else if (arg == "-l" || arg == "--loop") {
            cfg.loopForever = true;
        } else if (arg == "-q" || arg == "--quiet") {
            cfg.quiet = true;
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

using MacBytes = std::array<uint8_t, ETH_ALEN>;

static std::optional<MacBytes> macStringToBytes(const std::string& mac) {
    std::string hex;
    hex.reserve(12);

    for (const unsigned char ch : mac) {
        if (std::isxdigit(ch)) {
            hex.push_back(static_cast<char>(ch));
        }
    }

    if (hex.size() != 12) {
        return std::nullopt;
    }

    MacBytes bytes {};
    for (size_t i = 0; i < bytes.size(); ++i) {
        try {
            bytes[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
        } catch (...) {
            return std::nullopt;
        }
    }

    return bytes;
}

static bool ipInRange(uint32_t ip, const CidrRange& range) {
    return ip >= range.first && ip <= range.last;
}

static uint32_t chooseArpProbeSenderIp(
    const CidrRange& range,
    uint32_t targetIp,
    const std::set<std::string>& ownIpv4Addresses) {
    for (const auto& ownIp : ownIpv4Addresses) {
        const auto parsed = parseIpv4String(ownIp);
        if (parsed && ipInRange(*parsed, range) && *parsed != targetIp) {
            return *parsed;
        }
    }

    if (range.addressCount > 1) {
        if (range.first != targetIp) {
            return range.first;
        }
        return range.last;
    }

    return targetIp == 0xFFFFFFFFu ? targetIp - 1 : targetIp + 1;
}

static std::vector<uint8_t> buildArpProbeFrame(
    const MacBytes& srcMac,
    uint32_t senderIp,
    uint32_t targetIp) {
    std::vector<uint8_t> frame(sizeof(struct ether_header) + sizeof(struct ether_arp));

    auto* eth = reinterpret_cast<struct ether_header*>(frame.data());
    std::memset(eth->ether_dhost, 0xff, ETH_ALEN);
    std::memcpy(eth->ether_shost, srcMac.data(), ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_ARP);

    auto* arp = reinterpret_cast<struct ether_arp*>(frame.data() + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    std::memcpy(arp->arp_sha, srcMac.data(), ETH_ALEN);
    std::memset(arp->arp_tha, 0x00, ETH_ALEN);

    const uint32_t senderIpBe = htonl(senderIp);
    const uint32_t targetIpBe = htonl(targetIp);
    std::memcpy(arp->arp_spa, &senderIpBe, sizeof(senderIpBe));
    std::memcpy(arp->arp_tpa, &targetIpBe, sizeof(targetIpBe));

    return frame;
}

struct ArpProbeHit {
    uint32_t ip = 0;
    std::string mac;
};

static std::optional<ArpProbeHit> parseArpProbeReply(
    const uint8_t* frame,
    ssize_t len,
    const std::set<uint32_t>& targetIps) {
    if (len < static_cast<ssize_t>(sizeof(struct ether_header) + sizeof(struct ether_arp))) {
        return std::nullopt;
    }

    const auto* eth = reinterpret_cast<const struct ether_header*>(frame);
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) {
        return std::nullopt;
    }

    const auto* arp = reinterpret_cast<const struct ether_arp*>(frame + sizeof(struct ether_header));
    if (ntohs(arp->ea_hdr.ar_hrd) != ARPHRD_ETHER ||
        ntohs(arp->ea_hdr.ar_pro) != ETHERTYPE_IP ||
        arp->ea_hdr.ar_hln != ETH_ALEN ||
        arp->ea_hdr.ar_pln != 4 ||
        ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) {
        return std::nullopt;
    }

    uint32_t senderIpBe = 0;
    std::memcpy(&senderIpBe, arp->arp_spa, sizeof(senderIpBe));
    const uint32_t senderIp = ntohl(senderIpBe);
    if (targetIps.count(senderIp) == 0) {
        return std::nullopt;
    }

    return ArpProbeHit{senderIp, macToString(arp->arp_sha)};
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

static std::set<std::string> getInterfaceIpv4Addresses(const std::string& ifname) {
    std::set<std::string> addresses;
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) {
        return addresses;
    }

    for (const struct ifaddrs* entry = ifaddr; entry != nullptr; entry = entry->ifa_next) {
        if (!entry->ifa_addr || ifname != entry->ifa_name || entry->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        const auto* addr = reinterpret_cast<const struct sockaddr_in*>(entry->ifa_addr);
        addresses.insert(ipToString(addr->sin_addr.s_addr));
    }

    freeifaddrs(ifaddr);
    return addresses;
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

[[maybe_unused]] static void writeToStreams(
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

static std::filesystem::path rotatedLogPath(const std::filesystem::path& path, int index) {
    return std::filesystem::path(path.string() + "." + std::to_string(index));
}

static bool rotateLogFiles(
    const std::filesystem::path& path,
    int retainCount,
    std::string* errorMessage = nullptr) {
    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec) {
        if (errorMessage) {
            *errorMessage = "failed to inspect log file '" + path.string() + "': " + ec.message();
        }
        return false;
    }
    if (!exists) {
        return true;
    }

    if (retainCount <= 0) {
        std::filesystem::remove(path, ec);
        if (ec) {
            if (errorMessage) {
                *errorMessage = "failed to remove log file '" + path.string() + "': " + ec.message();
            }
            return false;
        }
        return true;
    }

    const auto oldest = rotatedLogPath(path, retainCount);
    std::filesystem::remove(oldest, ec);
    if (ec) {
        if (errorMessage) {
            *errorMessage = "failed to remove rotated log file '" + oldest.string() + "': " + ec.message();
        }
        return false;
    }

    for (int i = retainCount - 1; i >= 1; --i) {
        const auto source = rotatedLogPath(path, i);
        if (!std::filesystem::exists(source, ec)) {
            if (ec) {
                if (errorMessage) {
                    *errorMessage = "failed to inspect rotated log file '" + source.string() + "': " + ec.message();
                }
                return false;
            }
            continue;
        }

        const auto target = rotatedLogPath(path, i + 1);
        std::filesystem::remove(target, ec);
        if (ec) {
            if (errorMessage) {
                *errorMessage = "failed to replace rotated log file '" + target.string() + "': " + ec.message();
            }
            return false;
        }

        std::filesystem::rename(source, target, ec);
        if (ec) {
            if (errorMessage) {
                *errorMessage = "failed to rename '" + source.string() + "' to '" + target.string() + "': " + ec.message();
            }
            return false;
        }
    }

    const auto firstArchive = rotatedLogPath(path, 1);
    std::filesystem::remove(firstArchive, ec);
    if (ec) {
        if (errorMessage) {
            *errorMessage = "failed to replace rotated log file '" + firstArchive.string() + "': " + ec.message();
        }
        return false;
    }

    std::filesystem::rename(path, firstArchive, ec);
    if (ec) {
        if (errorMessage) {
            *errorMessage = "failed to rotate log file '" + path.string() + "': " + ec.message();
        }
        return false;
    }

    return true;
}

class RotatingLog {
public:
    explicit RotatingLog(const Config& cfg, std::ostream* errorStream = &std::cerr)
        : path_(cfg.outputPath),
          rotateBytes_(cfg.rotateBytes),
          retainCount_(cfg.retainCount),
          errorStream_(errorStream) {
        openForAppend();
    }

    void write(const std::string& message) {
        if (path_.empty()) {
            return;
        }
        if (!ensureOpen()) {
            return;
        }
        if (rotateBytes_ > 0 && currentSize_ > 0 && currentSize_ + message.size() > rotateBytes_) {
            if (!rotateNow()) {
                return;
            }
        }

        stream_ << message;
        if (!stream_) {
            warnOnce(writeErrorActive_, "failed to write log file '" + path_.string() + "'");
            stream_.close();
            stream_.clear();
            return;
        }

        writeErrorActive_ = false;
        currentSize_ += message.size();
    }

    void flush() {
        if (stream_) {
            stream_.flush();
        }
    }

private:
    bool ensureOpen() {
        return stream_.is_open() || openForAppend();
    }

    bool openForAppend() {
        currentSize_ = 0;
        std::error_code ec;
        if (std::filesystem::exists(path_, ec)) {
            currentSize_ = std::filesystem::file_size(path_, ec);
            if (ec) {
                warnOnce(openErrorActive_, "failed to read log size for '" + path_.string() + "': " + ec.message());
                currentSize_ = 0;
            }
        } else if (ec) {
            warnOnce(openErrorActive_, "failed to inspect log file '" + path_.string() + "': " + ec.message());
            return false;
        }

        stream_.close();
        stream_.clear();
        errno = 0;
        stream_.open(path_, std::ios::app);
        if (!stream_) {
            const int savedErrno = errno;
            warnOnce(openErrorActive_, "failed to open log file '" + path_.string() + "': " + std::strerror(savedErrno));
            return false;
        }

        openErrorActive_ = false;
        return true;
    }

    bool openFresh() {
        stream_.close();
        stream_.clear();
        errno = 0;
        stream_.open(path_, std::ios::out | std::ios::trunc);
        if (!stream_) {
            const int savedErrno = errno;
            warnOnce(openErrorActive_, "failed to create rotated log file '" + path_.string() + "': " + std::strerror(savedErrno));
            return false;
        }

        openErrorActive_ = false;
        currentSize_ = 0;
        return true;
    }

    bool rotateNow() {
        stream_.close();
        stream_.clear();

        std::string errorMessage;
        if (!rotateLogFiles(path_, retainCount_, &errorMessage)) {
            warnOnce(rotationErrorActive_, errorMessage);
            return openForAppend();
        }

        rotationErrorActive_ = false;
        return openFresh();
    }

    void warnOnce(bool& active, const std::string& message) {
        if (active) {
            return;
        }
        active = true;
        if (errorStream_) {
            *errorStream_ << "Warning: " << message << "\n";
        }
    }

    std::filesystem::path path_;
    std::uintmax_t rotateBytes_ = 0;
    int retainCount_ = 0;
    std::uintmax_t currentSize_ = 0;
    std::ofstream stream_;
    std::ostream* errorStream_ = nullptr;
    bool openErrorActive_ = false;
    bool rotationErrorActive_ = false;
    bool writeErrorActive_ = false;
};

static void writeToOutputs(
    const std::string& message,
    std::ostream* primary,
    RotatingLog* log) {
    if (primary) {
        *primary << message;
    }
    if (log) {
        log->write(message);
    }
}

static std::ostream* consoleOutput(const Config& cfg) {
    return cfg.quiet ? nullptr : &std::cout;
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

static std::string formatLoopContinuationLine() {
    return "Loop mode enabled: starting the next capture session.\n";
}

struct ArpProbeResult {
    CidrRange cidr;
    int probesSent = 0;
    std::map<uint32_t, std::string> replies;
};

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
        out << "================\n\n";
    }

    return out.str();
}

static std::string formatArpProbeReport(const Config& cfg, const ArpProbeResult& result) {
    std::ostringstream out;
    out << "\nARP probe result\n";
    out << "================\n";
    out << "Probe CIDR: " << formatCidrRange(result.cidr) << "\n";
    out << "ARP probes sent: " << result.probesSent << "\n";
    out << "Responding hosts: " << result.replies.size() << "\n";

    for (const auto& [ip, mac] : result.replies) {
        out << "  " << ipv4HostToString(ip) << " -> " << mac << "\n";
        const auto vendor = lookupMacVendor(mac);
        if (vendor) {
            out << "    vendor: " << *vendor << "\n";
        }
    }

    if (result.replies.empty()) {
        out << "No ARP replies received from this CIDR.\n";
    } else {
        const std::string firstIp = ipv4HostToString(result.replies.begin()->first);
        const auto suggestedLocalIp = suggestLocalTestAddress(firstIp, std::nullopt);
        if (suggestedLocalIp) {
            out << "\nSuggested next test for " << firstIp << ":\n";
            out << "  sudo ip addr add " << *suggestedLocalIp << " dev " << cfg.ifname << "\n";
            out << "  sudo ip link set " << cfg.ifname << " up\n";
            out << "  ping -I " << cfg.ifname << " " << firstIp << "\n";
        }
    }

    out << "================\n\n";
    return out.str();
}

static constexpr auto kInterfacePollInterval = std::chrono::milliseconds(250);
static constexpr auto kLoopRestartDelay = std::chrono::seconds(1);

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
    RotatingLog* logStream = nullptr) {
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
            writeToOutputs("Waiting for interface " + ifname + " to appear...\n", statusStream, logStream);
            announcedWait = true;
        }

        sleeper();
    }

    return std::nullopt;
}

static bool isTransientInterfaceError(int err) {
    return err == ENODEV || err == ENETDOWN || err == ENETRESET || err == ENXIO;
}

template <typename Resolver>
static bool interfaceNeedsRebind(
    const std::string& ifname,
    int boundIfindex,
    Resolver&& resolver) {
    const unsigned int currentIfindex = resolver(ifname.c_str());
    return currentIfindex == 0 || static_cast<int>(currentIfindex) != boundIfindex;
}

static bool interfaceNeedsRebind(const std::string& ifname, int boundIfindex) {
    return interfaceNeedsRebind(
        ifname,
        boundIfindex,
        [](const char* name) { return if_nametoindex(name); });
}

struct CaptureSocket {
    int fd = -1;
    int ifindex = 0;
    std::string ownMac;
    std::set<std::string> ownIpv4Addresses;

    CaptureSocket() = default;
    CaptureSocket(const CaptureSocket&) = delete;
    CaptureSocket& operator=(const CaptureSocket&) = delete;

    CaptureSocket(CaptureSocket&& other) noexcept {
        *this = std::move(other);
    }

    CaptureSocket& operator=(CaptureSocket&& other) noexcept {
        if (this != &other) {
            reset();
            fd = other.fd;
            ifindex = other.ifindex;
            ownMac = std::move(other.ownMac);
            ownIpv4Addresses = std::move(other.ownIpv4Addresses);
            other.fd = -1;
            other.ifindex = 0;
        }
        return *this;
    }

    ~CaptureSocket() {
        reset();
    }

    void reset() {
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        ifindex = 0;
        ownMac.clear();
        ownIpv4Addresses.clear();
    }
};

static std::optional<CaptureSocket> openCaptureSocket(
    const Config& cfg,
    int attempts,
    RotatingLog* logStream,
    bool reconnecting = false) {
    bool announcedWait = false;
    bool announcedUnstable = false;

    for (int attempt = 0; attempt < attempts; ++attempt) {
        const unsigned int ifindex = if_nametoindex(cfg.ifname.c_str());
        if (ifindex == 0) {
            if (!announcedWait) {
                const std::string message = reconnecting
                    ? "Interface " + cfg.ifname + " disappeared; waiting for it to return...\n"
                    : "Waiting for interface " + cfg.ifname + " to appear...\n";
                writeToOutputs(message, consoleOutput(cfg), logStream);
                announcedWait = true;
            }
            if (attempt + 1 < attempts) {
                std::this_thread::sleep_for(kInterfacePollInterval);
            }
            continue;
        }

        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0) {
            std::cerr << "socket() failed: " << std::strerror(errno) << "\n";
            return std::nullopt;
        }

        const auto ownMac = getInterfaceMac(fd, cfg.ifname);
        if (!ownMac) {
            close(fd);
            if (!announcedUnstable) {
                writeToOutputs(
                    "Interface " + cfg.ifname + " is not ready yet; waiting to retry...\n",
                    consoleOutput(cfg),
                    logStream);
                announcedUnstable = true;
            }
            if (attempt + 1 < attempts) {
                std::this_thread::sleep_for(kInterfacePollInterval);
            }
            continue;
        }

        struct sockaddr_ll sll{};
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = static_cast<int>(ifindex);

        if (bind(fd, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
            const int savedErrno = errno;
            close(fd);
            if (isTransientInterfaceError(savedErrno) || if_nametoindex(cfg.ifname.c_str()) == 0) {
                if (!announcedUnstable) {
                    writeToOutputs(
                        "Interface " + cfg.ifname + " changed while opening; waiting to retry...\n",
                        consoleOutput(cfg),
                        logStream);
                    announcedUnstable = true;
                }
                if (attempt + 1 < attempts) {
                    std::this_thread::sleep_for(kInterfacePollInterval);
                }
                continue;
            }

            std::cerr << "bind() failed: " << std::strerror(savedErrno) << "\n";
            return std::nullopt;
        }

        CaptureSocket captureSocket;
        captureSocket.fd = fd;
        captureSocket.ifindex = static_cast<int>(ifindex);
        captureSocket.ownMac = *ownMac;
        captureSocket.ownIpv4Addresses = getInterfaceIpv4Addresses(cfg.ifname);
        return captureSocket;
    }

    std::cerr << "Interface did not appear within timeout: " << cfg.ifname << "\n";
    return std::nullopt;
}

static void writeReconnectComplete(const Config& cfg, const CaptureSocket& captureSocket, RotatingLog* logStream) {
    std::ostringstream status;
    status << "Reconnected to " << cfg.ifname
           << " with interface index " << captureSocket.ifindex << ".\n";
    writeToOutputs(status.str(), consoleOutput(cfg), logStream);
}

static bool shouldIgnoreCapturedFrame(
    const uint8_t* frame,
    ssize_t len,
    const std::string& ownMac,
    const std::set<std::string>& ownIpv4Addresses,
    unsigned char packetType) {
    if (packetType == PACKET_OUTGOING) {
        return true;
    }

    if (len < static_cast<ssize_t>(sizeof(struct ether_header))) {
        return false;
    }

    const auto* eth = reinterpret_cast<const struct ether_header*>(frame);
    if (macToString(eth->ether_shost) == ownMac) {
        return true;
    }

    if (ownIpv4Addresses.empty()) {
        return false;
    }

    const uint16_t etherType = ntohs(eth->ether_type);
    if (etherType == ETHERTYPE_ARP) {
        if (len < static_cast<ssize_t>(sizeof(struct ether_header) + sizeof(struct ether_arp))) {
            return false;
        }

        const auto* arp = reinterpret_cast<const struct ether_arp*>(frame + sizeof(struct ether_header));
        uint32_t spa_be = 0;
        std::memcpy(&spa_be, arp->arp_spa, sizeof(spa_be));
        return ownIpv4Addresses.count(ipToString(spa_be)) > 0;
    }

    if (etherType == ETHERTYPE_IP) {
        if (len < static_cast<ssize_t>(sizeof(struct ether_header) + sizeof(struct iphdr))) {
            return false;
        }

        const auto* ip = reinterpret_cast<const struct iphdr*>(frame + sizeof(struct ether_header));
        if (ip->version != 4) {
            return false;
        }

        return ownIpv4Addresses.count(ipToString(ip->saddr)) > 0;
    }

    return false;
}

static void handleArp(const uint8_t* frame, ssize_t len, Observation& obs) {
    if (len < static_cast<ssize_t>(sizeof(struct ether_header) + sizeof(struct ether_arp))) {
        return;
    }

    const auto* eth = reinterpret_cast<const struct ether_header*>(frame);
    const auto* arp = reinterpret_cast<const struct ether_arp*>(frame + sizeof(struct ether_header));

    const uint16_t arpOp = ntohs(arp->ea_hdr.ar_op);
    if (arpOp != ARPOP_REQUEST && arpOp != ARPOP_REPLY) {
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

    if (arpOp == ARPOP_REPLY) {
        return;
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

static bool sendRawFrameToInterface(
    int fd,
    int ifindex,
    const std::vector<uint8_t>& frame,
    const MacBytes& dstMac) {
    struct sockaddr_ll addr {};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    std::memcpy(addr.sll_addr, dstMac.data(), ETH_ALEN);

    const ssize_t sent = sendto(
        fd,
        frame.data(),
        frame.size(),
        0,
        reinterpret_cast<struct sockaddr*>(&addr),
        sizeof(addr));

    if (sent < 0) {
        std::cerr << "sendto() failed while sending ARP probe: " << std::strerror(errno) << "\n";
        return false;
    }

    if (sent != static_cast<ssize_t>(frame.size())) {
        std::cerr << "sendto() sent a partial ARP probe frame\n";
        return false;
    }

    return true;
}

static void recordArpProbeReply(
    const uint8_t* frame,
    ssize_t len,
    unsigned char packetType,
    const std::set<uint32_t>& targetIps,
    ArpProbeResult& result,
    Observation& obs) {
    if (packetType == PACKET_OUTGOING) {
        return;
    }

    const auto hit = parseArpProbeReply(frame, len, targetIps);
    if (!hit) {
        return;
    }

    if (result.replies.emplace(hit->ip, hit->mac).second) {
        obs.macCount[hit->mac]++;
        obs.srcIpCount[ipv4HostToString(hit->ip)]++;
    }
}

static bool drainAvailableArpProbeReplies(
    int fd,
    const std::set<uint32_t>& targetIps,
    ArpProbeResult& result,
    Observation& obs,
    std::vector<uint8_t>& buf) {
    for (;;) {
        struct sockaddr_ll packetAddress {};
        socklen_t packetAddressLen = sizeof(packetAddress);
        const ssize_t n = recvfrom(
            fd,
            buf.data(),
            buf.size(),
            MSG_DONTWAIT,
            reinterpret_cast<struct sockaddr*>(&packetAddress),
            &packetAddressLen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return true;
            }
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "recv() failed while draining ARP probe replies: "
                      << std::strerror(errno) << "\n";
            return false;
        }

        recordArpProbeReply(
            buf.data(),
            n,
            packetAddress.sll_pkttype,
            targetIps,
            result,
            obs);
    }
}

static bool runArpProbeCidr(
    const Config& cfg,
    const CaptureSocket& captureSocket,
    Observation& obs,
    ArpProbeResult& result,
    RotatingLog* logStream) {
    if (!cfg.probeCidr) {
        return true;
    }

    const auto ownMacBytes = macStringToBytes(captureSocket.ownMac);
    if (!ownMacBytes) {
        std::cerr << "Failed to parse interface MAC address for ARP probing: "
                  << captureSocket.ownMac << "\n";
        return false;
    }

    result = ArpProbeResult{};
    result.cidr = *cfg.probeCidr;

    std::set<uint32_t> targetIps;
    for (uint32_t ip = result.cidr.first;; ++ip) {
        targetIps.insert(ip);
        if (ip == result.cidr.last) {
            break;
        }
    }

    writeToOutputs(
        "ARP probing " + formatCidrRange(result.cidr) + " on " + cfg.ifname + "...\n",
        consoleOutput(cfg),
        logStream);

    MacBytes broadcast {};
    broadcast.fill(0xff);
    std::vector<uint8_t> buf(65536);

    for (const uint32_t targetIp : targetIps) {
        const uint32_t senderIp = chooseArpProbeSenderIp(
            result.cidr,
            targetIp,
            captureSocket.ownIpv4Addresses);
        const auto frame = buildArpProbeFrame(*ownMacBytes, senderIp, targetIp);
        if (!sendRawFrameToInterface(captureSocket.fd, captureSocket.ifindex, frame, broadcast)) {
            return false;
        }
        ++result.probesSent;

        if (result.probesSent % 256 == 0 &&
            !drainAvailableArpProbeReplies(captureSocket.fd, targetIps, result, obs, buf)) {
            return false;
        }
    }

    if (!drainAvailableArpProbeReplies(captureSocket.fd, targetIps, result, obs, buf)) {
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.timeoutSec);

    while (std::chrono::steady_clock::now() < deadline) {
        const auto now = std::chrono::steady_clock::now();
        auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        const auto maxSelectWait = std::chrono::duration_cast<std::chrono::microseconds>(
            kInterfacePollInterval);
        if (remaining > maxSelectWait) {
            remaining = maxSelectWait;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(captureSocket.fd, &rfds);

        struct timeval tv {};
        tv.tv_sec = remaining.count() / 1000000;
        tv.tv_usec = remaining.count() % 1000000;

        const int rc = select(captureSocket.fd + 1, &rfds, nullptr, nullptr, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "select() failed while waiting for ARP probe replies: "
                      << std::strerror(errno) << "\n";
            return false;
        }
        if (rc == 0) {
            continue;
        }

        struct sockaddr_ll packetAddress {};
        socklen_t packetAddressLen = sizeof(packetAddress);
        const ssize_t n = recvfrom(
            captureSocket.fd,
            buf.data(),
            buf.size(),
            0,
            reinterpret_cast<struct sockaddr*>(&packetAddress),
            &packetAddressLen);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "recv() failed while reading ARP probe replies: "
                      << std::strerror(errno) << "\n";
            return false;
        }

        recordArpProbeReply(
            buf.data(),
            n,
            packetAddress.sll_pkttype,
            targetIps,
            result,
            obs);
    }

    return true;
}

static int runCaptureSession(const Config& cfg, RotatingLog* logStream) {
    writeToOutputs(formatRunTimestampLine(currentLocalTimestamp()), consoleOutput(cfg), logStream);

    auto captureSocketOpt = openCaptureSocket(
        cfg,
        interfacePollAttempts(cfg.timeoutSec),
        logStream);
    if (!captureSocketOpt) {
        return 1;
    }
    CaptureSocket captureSocket = std::move(*captureSocketOpt);

    {
        std::ostringstream status;
        status << "Listening on " << cfg.ifname
               << " for up to " << cfg.maxPackets
               << " packets or " << cfg.timeoutSec << " seconds...\n";
        writeToOutputs(status.str(), consoleOutput(cfg), logStream);
    }

    Observation obs;
    if (cfg.probeCidr) {
        ArpProbeResult probeResult;
        if (!runArpProbeCidr(cfg, captureSocket, obs, probeResult, logStream)) {
            return 1;
        }
        writeToOutputs(formatArpProbeReport(cfg, probeResult), consoleOutput(cfg), logStream);
    }

    std::vector<uint8_t> buf(65536);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.timeoutSec);

    auto reconnect = [&]() -> bool {
        const auto reconnectStarted = std::chrono::steady_clock::now();
        auto reopened = openCaptureSocket(
            cfg,
            interfacePollAttempts(cfg.timeoutSec),
            logStream,
            true);
        const auto reconnectFinished = std::chrono::steady_clock::now();
        deadline += reconnectFinished - reconnectStarted;

        if (!reopened) {
            return false;
        }

        captureSocket = std::move(*reopened);
        writeReconnectComplete(cfg, captureSocket, logStream);
        return true;
    };

    int captured = 0;
    while (captured < cfg.maxPackets) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            writeToOutputs("Timeout reached.\n", consoleOutput(cfg), logStream);
            break;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(deadline - now);
        auto selectWait = remaining;
        const auto maxSelectWait = std::chrono::duration_cast<std::chrono::microseconds>(
            kInterfacePollInterval);
        if (selectWait > maxSelectWait) {
            selectWait = maxSelectWait;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(captureSocket.fd, &rfds);

        struct timeval tv{};
        tv.tv_sec = selectWait.count() / 1000000;
        tv.tv_usec = selectWait.count() % 1000000;

        int rc = select(captureSocket.fd + 1, &rfds, nullptr, nullptr, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "select() failed: " << std::strerror(errno) << "\n";
            return 1;
        }
        if (rc == 0) {
            if (interfaceNeedsRebind(cfg.ifname, captureSocket.ifindex)) {
                if (!reconnect()) {
                    return 1;
                }
            }
            continue;
        }

        struct sockaddr_ll packetAddress{};
        socklen_t packetAddressLen = sizeof(packetAddress);
        ssize_t n = recvfrom(
            captureSocket.fd,
            buf.data(),
            buf.size(),
            0,
            reinterpret_cast<struct sockaddr*>(&packetAddress),
            &packetAddressLen);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (isTransientInterfaceError(errno) || interfaceNeedsRebind(cfg.ifname, captureSocket.ifindex)) {
                if (!reconnect()) {
                    return 1;
                }
                continue;
            }
            std::cerr << "recv() failed: " << std::strerror(errno) << "\n";
            return 1;
        }

        if (n < static_cast<ssize_t>(sizeof(struct ether_header))) {
            continue;
        }

        if (shouldIgnoreCapturedFrame(
                buf.data(),
                n,
                captureSocket.ownMac,
                captureSocket.ownIpv4Addresses,
                packetAddress.sll_pkttype)) {
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

    writeToOutputs(formatInferenceReport(cfg, captured, obs), consoleOutput(cfg), logStream);

    return 0;
}

#ifndef INFER_IOT_RAW_TEST
int main(int argc, char* argv[]) {
    Config cfg;
    if (!parseArgs(argc, argv, cfg)) {
        return (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) ? 0 : 1;
    }

    RotatingLog logFile(cfg);
    RotatingLog* logStream = &logFile;
    logFile.write("=== infer_iot_raw run at " + currentLocalTimestamp() + " ===\n");

    do {
        if (runCaptureSession(cfg, logStream) != 0) {
            return 1;
        }

        if (!cfg.loopForever) {
            break;
        }

        writeToOutputs(formatLoopContinuationLine(), consoleOutput(cfg), logStream);
        logFile.write("\n");
        logFile.flush();
        std::this_thread::sleep_for(kLoopRestartDelay);
    } while (true);

    logFile.write("\n");
    logFile.flush();

    return 0;
}
#endif
