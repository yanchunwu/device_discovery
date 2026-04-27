#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <cstring>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../infer_iot_raw.cpp"

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::vector<char*> makeArgv(std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (std::string& arg : args) {
        argv.push_back(arg.data());
    }
    return argv;
}

std::string readTextFile(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

std::vector<uint8_t> buildArpRequest(
    const uint8_t (&srcMac)[6],
    const std::string& senderIp,
    const std::string& targetIp) {
    std::vector<uint8_t> frame(sizeof(struct ether_header) + sizeof(struct ether_arp));
    auto* eth = reinterpret_cast<struct ether_header*>(frame.data());
    std::memset(eth->ether_dhost, 0xff, ETH_ALEN);
    std::memcpy(eth->ether_shost, srcMac, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_ARP);

    auto* arp = reinterpret_cast<struct ether_arp*>(frame.data() + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    std::memcpy(arp->arp_sha, srcMac, ETH_ALEN);
    std::memset(arp->arp_tha, 0x00, ETH_ALEN);

    in_addr senderAddr {};
    in_addr targetAddr {};
    expect(inet_pton(AF_INET, senderIp.c_str(), &senderAddr) == 1, "invalid sender IP fixture");
    expect(inet_pton(AF_INET, targetIp.c_str(), &targetAddr) == 1, "invalid target IP fixture");
    std::memcpy(arp->arp_spa, &senderAddr.s_addr, sizeof(senderAddr.s_addr));
    std::memcpy(arp->arp_tpa, &targetAddr.s_addr, sizeof(targetAddr.s_addr));

    return frame;
}

std::vector<uint8_t> buildUdpIpv4Frame(
    const uint8_t (&srcMac)[6],
    const std::string& srcIp,
    const std::string& dstIp,
    uint16_t dstPort) {
    std::vector<uint8_t> frame(
        sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
    auto* eth = reinterpret_cast<struct ether_header*>(frame.data());
    std::memset(eth->ether_dhost, 0xff, ETH_ALEN);
    std::memcpy(eth->ether_shost, srcMac, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_IP);

    auto* ip = reinterpret_cast<struct iphdr*>(frame.data() + sizeof(struct ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = IPPROTO_UDP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
    expect(inet_pton(AF_INET, srcIp.c_str(), &ip->saddr) == 1, "invalid source IP fixture");
    expect(inet_pton(AF_INET, dstIp.c_str(), &ip->daddr) == 1, "invalid destination IP fixture");

    auto* udp = reinterpret_cast<struct udphdr*>(
        frame.data() + sizeof(struct ether_header) + sizeof(struct iphdr));
    udp->dest = htons(dstPort);

    return frame;
}

struct StreamCapture {
    std::ostream& stream;
    std::streambuf* original = nullptr;
    std::ostringstream buffer;

    explicit StreamCapture(std::ostream& target) : stream(target), original(target.rdbuf(buffer.rdbuf())) {}

    ~StreamCapture() {
        stream.rdbuf(original);
    }
};

void testParseArgsAcceptsFlagsAndPositionalInterface() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-n", "64", "-t", "9", "eth9"};
    auto argv = makeArgv(args);

    expect(parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should accept valid input");
    expect(cfg.ifname == "eth9", "expected positional interface to populate config");
    expect(cfg.maxPackets == 64, "expected packet count to be parsed");
    expect(cfg.timeoutSec == 9, "expected timeout to be parsed");
    expect(cfg.outputPath == "infer_iot_raw.log", "expected default output path to be set");
    expect(!cfg.loopForever, "expected loop mode to be disabled by default");
}

void testParseArgsAcceptsCustomOutputPath() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-i", "eth0", "-o", "capture.log"};
    auto argv = makeArgv(args);

    expect(parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should accept output path");
    expect(cfg.ifname == "eth0", "expected interface flag to be parsed");
    expect(cfg.outputPath == "capture.log", "expected custom output path to be parsed");
}

void testParseArgsAcceptsRotationPolicy() {
    Config cfg;
    std::vector<std::string> args = {
        "infer_iot_raw", "-i", "eth0", "--rotate-size", "10M", "--retain", "7"};
    auto argv = makeArgv(args);

    expect(parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should accept rotation policy");
    expect(cfg.rotateBytes == 10ull * 1024ull * 1024ull, "expected rotate size to be parsed");
    expect(cfg.retainCount == 7, "expected retain count to be parsed");
}

void testParseArgsAcceptsLoopFlag() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-i", "eth0", "--loop"};
    auto argv = makeArgv(args);

    expect(parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should accept loop flag");
    expect(cfg.ifname == "eth0", "expected interface flag to be parsed");
    expect(cfg.loopForever, "expected loop mode to be enabled");
}

void testParseArgsAcceptsQuietFlag() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-i", "eth0", "--quiet"};
    auto argv = makeArgv(args);

    expect(parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should accept quiet flag");
    expect(cfg.ifname == "eth0", "expected interface flag to be parsed");
    expect(cfg.quiet, "expected quiet mode to be enabled");
}

void testParseArgsRejectsInvalidPacketCount() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-i", "eth0", "-n", "0"};
    auto argv = makeArgv(args);
    StreamCapture stdoutCapture(std::cout);
    StreamCapture stderrCapture(std::cerr);

    expect(!parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should reject zero packet count");
}

void testParseArgsRejectsInvalidRotateSize() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-i", "eth0", "--rotate-size", "12XB"};
    auto argv = makeArgv(args);
    StreamCapture stdoutCapture(std::cout);
    StreamCapture stderrCapture(std::cerr);

    expect(!parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should reject invalid rotate size");
}

void testParseArgsRejectsInvalidRetainCount() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-i", "eth0", "--retain", "-1"};
    auto argv = makeArgv(args);
    StreamCapture stdoutCapture(std::cout);
    StreamCapture stderrCapture(std::cerr);

    expect(!parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should reject negative retain count");
}

void testSuggestLocalTestAddressUsesDeviceOrGatewaySubnet() {
    const auto fromDevice = suggestLocalTestAddress(std::optional<std::string>("10.0.5.23"), std::nullopt);
    expect(fromDevice && *fromDevice == "10.0.5.10/24", "expected /24 suggestion from device IP");

    const auto fromGateway = suggestLocalTestAddress(std::nullopt, std::optional<std::string>("172.16.1.10"));
    expect(fromGateway && *fromGateway == "172.16.1.11/24", "expected host fallback to avoid .10 collision");
}

void testNormalizeOuiPrefixAcceptsMacFormats() {
    expect(normalizeOuiPrefix("b8:a4:4f:01:02:03") == "B8A44F", "expected colon-delimited MAC to normalize");
    expect(normalizeOuiPrefix("B8-A4-4F") == "B8A44F", "expected hyphenated OUI to normalize");
    expect(normalizeOuiPrefix("invalid") == "", "expected invalid OUI input to be rejected");
}

void testParseByteSizeAcceptsSuffixes() {
    std::uintmax_t value = 0;

    expect(parseByteSize("512", value) && value == 512, "expected plain byte size to parse");
    expect(parseByteSize("64K", value) && value == 64ull * 1024ull, "expected kilobyte suffix to parse");
    expect(parseByteSize("10mb", value) && value == 10ull * 1024ull * 1024ull, "expected case-insensitive suffix");
    expect(!parseByteSize("bad", value), "expected invalid size token to fail");
}

void testParseOuiLineExtractsVendorEntry() {
    const auto entry = parseOuiLine("B8A44F     (base 16)\t\tShenzhen Example Devices");
    expect(entry.has_value(), "expected IEEE base-16 line to parse");
    expect(entry->first == "B8A44F", "expected parsed OUI prefix");
    expect(entry->second == "Shenzhen Example Devices", "expected parsed vendor name");

    expect(!parseOuiLine("B8-A4-4F   (hex)\t\tIgnored").has_value(), "expected non-base-16 line to be ignored");
}

void testLookupMacVendorUsesLocalOuiFile() {
    const char* path = "/tmp/device_discovery_test_oui.txt";
    {
        std::ofstream output(path);
        output << "B8A44F     (base 16)\t\tShenzhen Example Devices\n";
        output << "00163E     (base 16)\t\tExample Hypervisor Vendor\n";
    }

    const auto vendor = lookupMacVendor("b8:a4:4f:01:02:03", {path});
    expect(vendor && *vendor == "Shenzhen Example Devices", "expected vendor lookup to match normalized OUI");

    const auto unknownVendor = lookupMacVendor("aa:bb:cc:01:02:03", {path});
    expect(!unknownVendor.has_value(), "expected unknown OUI to return no vendor");

    std::remove(path);
}

void testWriteToStreamsMirrorsMessage() {
    std::ostringstream primary;
    std::ostringstream secondary;

    writeToStreams("hello\n", &primary, &secondary);

    expect(primary.str() == "hello\n", "expected primary stream to receive message");
    expect(secondary.str() == "hello\n", "expected secondary stream to receive message");
}

void testRotateLogFilesShiftsArchives() {
    const std::filesystem::path base = "/tmp/device_discovery_rotate_files.log";
    const auto archive1 = rotatedLogPath(base, 1);
    const auto archive2 = rotatedLogPath(base, 2);
    const auto archive3 = rotatedLogPath(base, 3);
    std::filesystem::remove(base);
    std::filesystem::remove(archive1);
    std::filesystem::remove(archive2);
    std::filesystem::remove(archive3);

    {
        std::ofstream(base) << "current";
        std::ofstream(archive1) << "old-1";
        std::ofstream(archive2) << "old-2";
    }

    std::string errorMessage;
    expect(rotateLogFiles(base, 3, &errorMessage), "expected rotateLogFiles to succeed");
    expect(readTextFile(archive1) == "current", "expected current log to become .1");
    expect(readTextFile(archive2) == "old-1", "expected .1 archive to become .2");
    expect(readTextFile(archive3) == "old-2", "expected .2 archive to become .3");
    expect(!std::filesystem::exists(base), "expected current log path to be rotated away before reopening");

    std::filesystem::remove(base);
    std::filesystem::remove(archive1);
    std::filesystem::remove(archive2);
    std::filesystem::remove(archive3);
}

void testRotatingLogRotatesBeforeExceedingLimit() {
    const std::filesystem::path base = "/tmp/device_discovery_rotating_log.log";
    const auto archive1 = rotatedLogPath(base, 1);
    const auto archive2 = rotatedLogPath(base, 2);
    std::filesystem::remove(base);
    std::filesystem::remove(archive1);
    std::filesystem::remove(archive2);

    Config cfg;
    cfg.outputPath = base.string();
    cfg.rotateBytes = 10;
    cfg.retainCount = 2;

    {
        std::ofstream(base) << "12345678";
    }

    RotatingLog log(cfg, nullptr);
    log.write("abc");
    log.flush();
    expect(readTextFile(archive1) == "12345678", "expected existing file to rotate to .1");
    expect(readTextFile(base) == "abc", "expected current log to contain the new message");

    log.write("0123456789");
    log.flush();
    expect(readTextFile(archive2) == "12345678", "expected oldest rotated file to shift to .2");
    expect(readTextFile(archive1) == "abc", "expected previous current log to become .1");
    expect(readTextFile(base) == "0123456789", "expected new current log file to contain the latest write");

    std::filesystem::remove(base);
    std::filesystem::remove(archive1);
    std::filesystem::remove(archive2);
}

void testFormatRunTimestampLineUsesExpectedPrefix() {
    expect(
        formatRunTimestampLine("2026-04-22 10:11:12") == "Timestamp: 2026-04-22 10:11:12\n",
        "expected startup timestamp line to use the documented format");
}

void testFormatLoopContinuationLineUsesExpectedText() {
    expect(
        formatLoopContinuationLine() == "Loop mode enabled: starting the next capture session.\n",
        "expected loop continuation line to use the documented format");
}

void testFormatInferenceReportIncludesSummary() {
    Config cfg;
    cfg.ifname = "eth7";
    Observation obs;
    obs.macCount["00:16:3e:aa:bb:cc"] = 3;
    obs.srcIpCount["192.168.50.23"] = 2;
    obs.arpGatewayCount["192.168.50.1"] = 1;
    obs.linkLocalProbes.insert("169.254.44.55");
    obs.sawSSDP = true;

    const std::string report = formatInferenceReport(cfg, 7, obs);

    expect(report.find("Captured packets: 7\n") != std::string::npos, "expected packet count in report");
    expect(report.find("Likely device MAC: 00:16:3e:aa:bb:cc\n") != std::string::npos, "expected device MAC in report");
    expect(report.find("Likely device IP: 192.168.50.23\n") != std::string::npos, "expected device IP in report");
    expect(report.find("Likely gateway IP: 192.168.50.1\n") != std::string::npos, "expected gateway IP in report");
    expect(report.find("Link-local probe(s):\n  - 169.254.44.55\n") != std::string::npos, "expected link-local probe list in report");
    expect(report.find("SSDP observed: yes\n") != std::string::npos, "expected SSDP summary in report");
    expect(report.find("sudo ip addr add 192.168.50.10/24 dev eth7\n") != std::string::npos, "expected suggested local address in report");
}

void testInterfacePollAttemptsCoversTimeoutWindow() {
    expect(interfacePollAttempts(1) == 5, "1 second timeout should result in five polls at 250ms intervals");
    expect(interfacePollAttempts(3) == 13, "3 second timeout should result in thirteen polls including the initial check");
}

void testWaitForInterfaceReturnsWhenInterfaceAppears() {
    std::vector<unsigned int> responses = {0, 0, 17};
    size_t resolverCallCount = 0;
    int sleepCallCount = 0;
    std::ostringstream status;

    const auto ifindex = waitForInterface(
        "enxdeadbeef",
        5,
        [&](const char*) {
            return responses.at(resolverCallCount++);
        },
        [&]() {
            ++sleepCallCount;
        },
        &status);

    expect(ifindex && *ifindex == 17, "expected interface wait to return the discovered index");
    expect(resolverCallCount == 3, "expected polling to stop once the interface appears");
    expect(sleepCallCount == 2, "expected sleeps only between failed polls");
    expect(status.str() == "Waiting for interface enxdeadbeef to appear...\n", "expected one wait status message");
}

void testWaitForInterfaceTimesOutCleanly() {
    int resolverCallCount = 0;
    int sleepCallCount = 0;

    const auto ifindex = waitForInterface(
        "missing0",
        4,
        [&](const char*) {
            ++resolverCallCount;
            return 0u;
        },
        [&]() {
            ++sleepCallCount;
        });

    expect(!ifindex, "expected missing interface to time out without crashing");
    expect(resolverCallCount == 4, "expected resolver to be called for every poll attempt");
    expect(sleepCallCount == 3, "expected no sleep after the final failed poll");
}

void testTransientInterfaceErrorsAreRecoverable() {
    expect(isTransientInterfaceError(ENODEV), "ENODEV should trigger interface recovery");
    expect(isTransientInterfaceError(ENETDOWN), "ENETDOWN should trigger interface recovery");
    expect(isTransientInterfaceError(ENETRESET), "ENETRESET should trigger interface recovery");
    expect(isTransientInterfaceError(ENXIO), "ENXIO should trigger interface recovery");
    expect(!isTransientInterfaceError(EACCES), "permission errors should stay fatal");
}

void testInterfaceNeedsRebindDetectsMissingOrReplacedInterface() {
    expect(
        !interfaceNeedsRebind(
            "eth0",
            17,
            [](const char*) {
                return 17u;
            }),
        "same interface index should not need rebind");

    expect(
        interfaceNeedsRebind(
            "eth0",
            17,
            [](const char*) {
                return 0u;
            }),
        "missing interface should need rebind");

    expect(
        interfaceNeedsRebind(
            "eth0",
            17,
            [](const char*) {
                return 18u;
            }),
        "changed interface index should need rebind");
}

void testShouldIgnoreCapturedFrameFiltersOwnAndOutgoingTraffic() {
    const uint8_t ownMac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t deviceMac[6] = {0xb8, 0xa4, 0x4f, 0x01, 0x02, 0x03};
    const auto ownFrame = buildArpRequest(ownMac, "192.168.10.10", "192.168.10.1");
    const auto deviceFrame = buildArpRequest(deviceMac, "192.168.10.44", "192.168.10.1");

    expect(
        shouldIgnoreCapturedFrame(
            ownFrame.data(),
            static_cast<ssize_t>(ownFrame.size()),
            "02:11:22:33:44:55",
            {},
            PACKET_BROADCAST),
        "frames from the capture NIC MAC should be ignored");

    expect(
        shouldIgnoreCapturedFrame(
            deviceFrame.data(),
            static_cast<ssize_t>(deviceFrame.size()),
            "02:11:22:33:44:55",
            {},
            PACKET_OUTGOING),
        "Linux packet-socket outgoing frames should be ignored");

    expect(
        !shouldIgnoreCapturedFrame(
            deviceFrame.data(),
            static_cast<ssize_t>(deviceFrame.size()),
            "02:11:22:33:44:55",
            {},
            PACKET_BROADCAST),
        "inbound frames from a different MAC should be captured");
}

void testShouldIgnoreCapturedFrameFiltersOwnIpv4Traffic() {
    const uint8_t otherMac[6] = {0x0e, 0x9e, 0x5d, 0x2d, 0xf6, 0xf5};
    const auto arpFrame = buildArpRequest(otherMac, "169.254.207.168", "169.254.207.1");
    const auto ipv4Frame = buildUdpIpv4Frame(otherMac, "169.254.207.168", "239.255.255.250", 1900);
    const std::set<std::string> ownIpv4Addresses = {"169.254.207.168"};

    expect(
        shouldIgnoreCapturedFrame(
            arpFrame.data(),
            static_cast<ssize_t>(arpFrame.size()),
            "02:11:22:33:44:55",
            ownIpv4Addresses,
            PACKET_BROADCAST),
        "ARP frames with the interface's own sender IP should be ignored");

    expect(
        shouldIgnoreCapturedFrame(
            ipv4Frame.data(),
            static_cast<ssize_t>(ipv4Frame.size()),
            "02:11:22:33:44:55",
            ownIpv4Addresses,
            PACKET_MULTICAST),
        "IPv4 frames with the interface's own source IP should be ignored");

    expect(
        !shouldIgnoreCapturedFrame(
            arpFrame.data(),
            static_cast<ssize_t>(arpFrame.size()),
            "02:11:22:33:44:55",
            {"169.254.207.169"},
            PACKET_BROADCAST),
        "frames from another source IP should still be captured");
}

void testHandleArpTracksGatewayAndLinkLocalProbe() {
    const uint8_t srcMac[6] = {0xb8, 0xa4, 0x4f, 0x01, 0x02, 0x03};
    Observation obs;

    const auto gatewayFrame = buildArpRequest(srcMac, "192.168.10.44", "192.168.10.1");
    handleArp(gatewayFrame.data(), static_cast<ssize_t>(gatewayFrame.size()), obs);

    expect(obs.macCount["b8:a4:4f:01:02:03"] == 1, "expected ARP request to count source MAC");
    expect(obs.srcIpCount["192.168.10.44"] == 1, "expected ARP sender IP to be counted");
    expect(obs.arpGatewayCount["192.168.10.1"] == 1, "expected ARP target IP to be treated as gateway candidate");

    const auto probeFrame = buildArpRequest(srcMac, "0.0.0.0", "169.254.77.88");
    handleArp(probeFrame.data(), static_cast<ssize_t>(probeFrame.size()), obs);

    expect(obs.linkLocalProbes.count("169.254.77.88") == 1, "expected link-local ARP probe to be recorded");
    expect(obs.srcIpCount.count("0.0.0.0") == 0, "0.0.0.0 should not be counted as a usable source IP");
}

void testHandleIpv4TracksSourceAndDetectsSsdp() {
    const uint8_t srcMac[6] = {0x00, 0x16, 0x3e, 0xaa, 0xbb, 0xcc};
    Observation obs;

    const auto frame = buildUdpIpv4Frame(srcMac, "10.1.2.3", "239.255.255.250", 1900);
    handleIpv4(frame.data(), static_cast<ssize_t>(frame.size()), obs);

    expect(obs.macCount["00:16:3e:aa:bb:cc"] == 1, "expected IPv4 packet to count source MAC");
    expect(obs.srcIpCount["10.1.2.3"] == 1, "expected IPv4 source IP to be counted");
    expect(obs.sawSSDP, "expected SSDP multicast traffic to be detected");
}

}  // namespace

int main() {
    const struct TestCase {
        const char* name;
        void (*fn)();
    } tests[] = {
        {"parseArgs accepts flags and positional interface", testParseArgsAcceptsFlagsAndPositionalInterface},
        {"parseArgs accepts custom output path", testParseArgsAcceptsCustomOutputPath},
        {"parseArgs accepts rotation policy", testParseArgsAcceptsRotationPolicy},
        {"parseArgs accepts loop flag", testParseArgsAcceptsLoopFlag},
        {"parseArgs accepts quiet flag", testParseArgsAcceptsQuietFlag},
        {"parseArgs rejects invalid packet count", testParseArgsRejectsInvalidPacketCount},
        {"parseArgs rejects invalid rotate size", testParseArgsRejectsInvalidRotateSize},
        {"parseArgs rejects invalid retain count", testParseArgsRejectsInvalidRetainCount},
        {"suggestLocalTestAddress uses device or gateway subnet", testSuggestLocalTestAddressUsesDeviceOrGatewaySubnet},
        {"normalizeOuiPrefix accepts MAC formats", testNormalizeOuiPrefixAcceptsMacFormats},
        {"parseByteSize accepts suffixes", testParseByteSizeAcceptsSuffixes},
        {"parseOuiLine extracts vendor entry", testParseOuiLineExtractsVendorEntry},
        {"lookupMacVendor uses local OUI file", testLookupMacVendorUsesLocalOuiFile},
        {"writeToStreams mirrors message", testWriteToStreamsMirrorsMessage},
        {"rotateLogFiles shifts archives", testRotateLogFilesShiftsArchives},
        {"RotatingLog rotates before exceeding limit", testRotatingLogRotatesBeforeExceedingLimit},
        {"formatRunTimestampLine uses expected prefix", testFormatRunTimestampLineUsesExpectedPrefix},
        {"formatLoopContinuationLine uses expected text", testFormatLoopContinuationLineUsesExpectedText},
        {"formatInferenceReport includes summary", testFormatInferenceReportIncludesSummary},
        {"interfacePollAttempts covers timeout window", testInterfacePollAttemptsCoversTimeoutWindow},
        {"waitForInterface returns when interface appears", testWaitForInterfaceReturnsWhenInterfaceAppears},
        {"waitForInterface times out cleanly", testWaitForInterfaceTimesOutCleanly},
        {"transient interface errors are recoverable", testTransientInterfaceErrorsAreRecoverable},
        {"interfaceNeedsRebind detects missing or replaced interface", testInterfaceNeedsRebindDetectsMissingOrReplacedInterface},
        {"shouldIgnoreCapturedFrame filters own and outgoing traffic", testShouldIgnoreCapturedFrameFiltersOwnAndOutgoingTraffic},
        {"shouldIgnoreCapturedFrame filters own IPv4 traffic", testShouldIgnoreCapturedFrameFiltersOwnIpv4Traffic},
        {"handleArp tracks gateway and link-local probe", testHandleArpTracksGatewayAndLinkLocalProbe},
        {"handleIpv4 tracks source and detects SSDP", testHandleIpv4TracksSourceAndDetectsSsdp},
    };

    int passed = 0;
    for (const auto& test : tests) {
        try {
            test.fn();
            ++passed;
        } catch (const std::exception& ex) {
            std::cerr << "FAIL: " << test.name << ": " << ex.what() << "\n";
            return 1;
        }
    }

    std::cout << "Passed " << passed << " tests\n";
    return 0;
}
