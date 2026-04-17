# device_discovery

`device_discovery` is a small Linux command-line utility for observing raw Ethernet traffic on an interface and inferring likely IoT device network details from ARP and IPv4/UDP packets.

It is designed for cases where a device is easiest to identify during boot or first-link activity, such as after power-cycling an IoT device on an isolated network segment.

## Features

- Captures raw Ethernet frames on a selected interface
- Infers a likely device MAC address
- Infers a likely device IP address
- Infers a likely gateway IP address from ARP traffic
- Detects link-local probing activity
- Detects SSDP traffic to `239.255.255.250:1900`
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
sudo ./bin/infer_iot_raw enx000ec6bc22b0
```

Or with explicit options:

```bash
sudo ./bin/infer_iot_raw -i enx000ec6bc22b0 -n 100 -t 15
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
source /opt/bg/device_discovery/completions/infer_iot_raw
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
