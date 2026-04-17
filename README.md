# IOT device discovery

`device_discovery` is a small Linux command-line utility focused on IOT device discovery. It listens to raw Ethernet traffic on a selected interface and infers likely device network details from ARP and IPv4/UDP packets.

It is intended for the common bring-up and reverse-engineering case where an IOT device is easiest to identify during boot, DHCP, ARP probing, or first-link activity. The typical workflow is to connect the device to an isolated segment, start capture, and then power-cycle the device so its initial network behavior can be observed and narrowed to a likely MAC, IP, and gateway.

## IOT Discovery Use Case

This tool is most useful when you need to answer questions like:

- What MAC address does this IOT device use when it first comes online?
- Does it request or probe for a specific IP address?
- Is it using link-local addressing before it gets configured?
- Does it advertise itself with SSDP or other early network traffic?
- What gateway or network range does it appear to expect?

## Features

- Captures raw Ethernet frames on a selected interface
- Infers a likely IOT device MAC address
- Infers a likely IOT device IP address
- Infers a likely gateway IP address from ARP traffic
- Detects link-local probing activity during device discovery
- Detects SSDP traffic to `239.255.255.250:1900` during early device startup
- Supports Bash autocompletion for flags and interface names

## Requirements

- Linux
- `g++` with C++17 support
- `make`
- Root privileges or `CAP_NET_RAW`

## Build

Build the binary into `bin/`:

```bash
make
```

The executable will be created at:

```bash
bin/infer_iot_raw
```

To remove the built binary:

```bash
make clean
```

To grant the binary raw-socket capability without running as root:

```bash
make install-cap
```

## Usage

Show help:

```bash
./bin/infer_iot_raw --help
```

Run against an interface:

```bash
sudo ./bin/infer_iot_raw eth1
```

Or with explicit options:

```bash
sudo ./bin/infer_iot_raw -i eth1 -n 100 -t 15
```

Supported options:

- `-i`, `--interface <name>`: network interface to listen on
- `-n`, `--packets <count>`: maximum packets to capture
- `-t`, `--timeout <sec>`: stop after the given timeout
- `-h`, `--help`: show help output

Example output:

```text
./infer_iot_raw --interface eth1
Listening on eth1 for up to 200 packets or 30 seconds...

Inference result
================
Captured packets: 200
Likely device MAC: b8:a4:4f:xx:xx:xx
Likely device IP: 0.0.0.0
Likely gateway IP: 172.19.0.1
Link-local probe(s):
  - 169.254.38.22
SSDP observed: yes

Suggested next test:
  sudo ip addr flush dev eth1
  sudo ip addr add 172.19.0.10/16 dev eth1
  sudo ip link set eth1 up
  ping -I eth1 0.0.0.0
```

## Bash Autocompletion

The repository includes a Bash completion script at `completions/infer_iot_raw`.

Load it in the current shell:

```bash
source device_discovery/completions/infer_iot_raw
```

Or install it system-wide:

```bash
make install-bash-completion
```

The completion script supports:

- option completion for `-h`, `--help`, `-i`, `--interface`, `-n`, `--packets`, `-t`, `--timeout`
- interface-name completion from `/sys/class/net`
- command completion for `infer_iot_raw`, `./infer_iot_raw`, `bin/infer_iot_raw`, and `./bin/infer_iot_raw`

## Typical Workflow

1. Build the tool with `make`.
2. Load or install Bash completion if desired.
3. Start capture on the target interface.
4. Power-cycle the IoT device.
5. Review the inferred MAC, IP, gateway, and link-local probe output.

If an IP address is inferred, the tool prints a suggested next-step network test at the end of execution.

## Repository Layout

- `infer_iot_raw.cpp`: program source
- `Makefile`: build, install, capability, and Bash completion install targets
- `completions/infer_iot_raw`: Bash completion script
- `bin/`: build output directory
