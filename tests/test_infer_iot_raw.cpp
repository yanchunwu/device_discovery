#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
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
}

void testParseArgsRejectsInvalidPacketCount() {
    Config cfg;
    std::vector<std::string> args = {"infer_iot_raw", "-i", "eth0", "-n", "0"};
    auto argv = makeArgv(args);
    StreamCapture stdoutCapture(std::cout);
    StreamCapture stderrCapture(std::cerr);

    expect(!parseArgs(static_cast<int>(argv.size()), argv.data(), cfg), "parseArgs should reject zero packet count");
}

void testSuggestLocalTestAddressUsesDeviceOrGatewaySubnet() {
    const auto fromDevice = suggestLocalTestAddress(std::optional<std::string>("10.0.5.23"), std::nullopt);
    expect(fromDevice && *fromDevice == "10.0.5.10/24", "expected /24 suggestion from device IP");

    const auto fromGateway = suggestLocalTestAddress(std::nullopt, std::optional<std::string>("172.16.1.10"));
    expect(fromGateway && *fromGateway == "172.16.1.11/24", "expected host fallback to avoid .10 collision");
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
        {"parseArgs rejects invalid packet count", testParseArgsRejectsInvalidPacketCount},
        {"suggestLocalTestAddress uses device or gateway subnet", testSuggestLocalTestAddressUsesDeviceOrGatewaySubnet},
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
