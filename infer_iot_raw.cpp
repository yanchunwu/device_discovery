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

struct Config {
    std::string ifname;
    int maxPackets = 200;
    int timeoutSec = 30;
    std::string outputPath = "infer_iot_raw.log";
    std::uintmax_t rotateBytes = 0;
    int retainCount = 5;
    bool loopForever = false;
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
        << "      --rotate-size <size> Rotate the log when it would exceed this size; 0 disables rotation\n"
        << "      --retain <count>     Number of rotated log files to keep (default: 5)\n"
        << "  -l, --loop               Repeat capture sessions forever\n"
        << "  -h, --help               Show this help message\n\n"
        << "Examples:\n"
        << "  sudo " << prog << " eth1\n"
        << "  sudo " << prog << " -i eth1 -n 100 -t 15\n"
        << "  sudo " << prog << " -i eth1 -o capture.log\n"
        << "  sudo " << prog << " -i eth1 -o capture.log --rotate-size 10M --retain 7\n"
        << "  sudo " << prog << " -i eth1 --loop\n\n"
        << "Notes:\n"
        << "  - Requires Linux.\n"
        << "  - Requires root or CAP_NET_RAW.\n"
        << "  - Best results come from starting capture, then power-cycling the IoT device.\n"
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

static int runCaptureSession(const Config& cfg, RotatingLog* logStream) {
    writeToOutputs(formatRunTimestampLine(currentLocalTimestamp()), &std::cout, logStream);

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
        writeToOutputs(status.str(), &std::cout, logStream);
    }

    Observation obs;
    std::vector<uint8_t> buf(65536);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(cfg.timeoutSec);

    int captured = 0;
    while (captured < cfg.maxPackets) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            writeToOutputs("Timeout reached.\n", &std::cout, logStream);
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
            writeToOutputs("Timeout reached.\n", &std::cout, logStream);
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

    writeToOutputs(formatInferenceReport(cfg, captured, obs), &std::cout, logStream);

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

        writeToOutputs(formatLoopContinuationLine(), &std::cout, logStream);
        logFile.write("\n");
        logFile.flush();
        std::this_thread::sleep_for(kLoopRestartDelay);
    } while (true);

    logFile.write("\n");
    logFile.flush();

    return 0;
}
#endif
