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
- Looks up the likely device vendor from the MAC OUI when a local IEEE OUI database is available
- Infers a likely IOT device IP address
- Infers a likely gateway IP address from ARP traffic
- Detects link-local probing activity during device discovery
- Detects SSDP traffic to `239.255.255.250:1900` during early device startup
- Appends normal run output to `infer_iot_raw.log` in the current directory by default
- Can repeat capture sessions indefinitely with `--loop`
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

Run the unit tests:

```bash
make test
```

Install the binary to the default prefix:

```bash
sudo make install
```

The default install path is `/usr/local/bin/infer_iot_raw`.

`sudo make install` also applies `cap_net_raw` to the installed binary so it can open raw sockets without requiring a separate manual `setcap` step.

To choose a different install prefix:

```bash
make install PREFIX=$HOME/.local
sudo make install PREFIX=/usr
```

To stage an install into a packaging or rootfs directory:

```bash
make install DESTDIR=/tmp/pkgroot PREFIX=/usr
```

To re-apply the raw-socket capability to the installed binary after installation:

```bash
sudo make install-cap
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

Or choose a custom log filename:

```bash
sudo ./bin/infer_iot_raw -i eth1 -o my-capture.log
```

Or keep running capture sessions forever:

```bash
sudo ./bin/infer_iot_raw -i eth1 --loop
```

If the named interface is not present yet, the program waits for it to appear for up to the configured timeout, then starts capture once the interface exists.

If the system has an IEEE OUI database installed, the output also includes a likely vendor name for the inferred device MAC.

By default, normal run output is also appended to `./infer_iot_raw.log`. Use `-o` or `--output` to change the log filename or path.

Use `-l` or `--loop` to restart capture automatically after each inference report instead of exiting.

Supported options:

- `-i`, `--interface <name>`: network interface to listen on
- `-n`, `--packets <count>`: maximum packets to capture
- `-t`, `--timeout <sec>`: stop after the given timeout
- `-o`, `--output <path>`: log file path, default `infer_iot_raw.log`
- `-l`, `--loop`: repeat capture sessions forever
- `-h`, `--help`: show help output

Example output:

```text
./infer_iot_raw --interface eth1
Timestamp: 2026-04-22 10:11:12
Listening on eth1 for up to 200 packets or 30 seconds...

Inference result
================
Captured packets: 200
Likely device MAC: b8:a4:4f:xx:xx:xx
Likely device vendor: Shenzhen Example Devices
Likely device IP: 0.0.0.0
Likely gateway IP: 172.19.0.1
Link-local probe(s):
  - 169.254.38.22
SSDP observed: yes

Suggested next test:
  sudo ip addr flush dev eth1
  sudo ip addr add 172.19.0.10/24 dev eth1
  sudo ip link set eth1 up

Loop mode enabled: starting the next capture session.
```

## Bash Autocompletion

The repository includes a Bash completion script at `completions/infer_iot_raw.bash`.

Load it in the current shell:

```bash
source /opt/bg/device_discovery/completions/infer_iot_raw.bash
```

If you are already in the repository root, this also works:

```bash
source completions/infer_iot_raw.bash
```

To load it automatically in future Bash sessions, add this line to your `~/.bashrc`:

```bash
[ -f /opt/bg/device_discovery/completions/infer_iot_raw.bash ] && source /opt/bg/device_discovery/completions/infer_iot_raw.bash
```

Or install it system-wide:

```bash
sudo make install-bash-completion
```

You can also override the install location or stage the completion file with the same `PREFIX` and `DESTDIR` variables used by `make install`.

The completion script supports:

- option completion for `-h`, `--help`, `-i`, `--interface`, `-n`, `--packets`, `-t`, `--timeout`, `-o`, `--output`, `-l`, `--loop`
- interface-name completion from `/sys/class/net`
- command completion for `infer_iot_raw`, `./infer_iot_raw`, `bin/infer_iot_raw`, and `./bin/infer_iot_raw`

## Systemd Service

The repository includes a helper script at `scripts/setup-systemd-service.sh` that installs the recommended hardened template unit using a dedicated `inferiot` service account.

Install the binary first:

```bash
sudo make install
```

Then run the setup script. Pass the interface name as the first argument if you do not want the default `enx000ec6bc22b0`:

```bash
chmod +x scripts/setup-systemd-service.sh
./scripts/setup-systemd-service.sh
./scripts/setup-systemd-service.sh enx000ec6bc22b0
```

If the binary is installed somewhere non-standard, override it explicitly when invoking the script:

```bash
BINARY=/path/to/infer_iot_raw ./scripts/setup-systemd-service.sh enx000ec6bc22b0
```

The script writes:

- `/etc/default/infer_iot_raw` with `PACKETS` and `TIMEOUT`
- `/etc/systemd/system/infer_iot_raw@.service` as a template unit
- `/var/lib/infer_iot_raw/infer_iot_raw-<interface>.log` as the runtime log path

You can override the packet and timeout defaults when invoking the script:

```bash
PACKETS=500000 TIMEOUT=1800 ./scripts/setup-systemd-service.sh enx000ec6bc22b0
```

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
- `completions/infer_iot_raw.bash`: Bash completion script
- `scripts/setup-systemd-service.sh`: helper for installing the hardened systemd template unit
- `bin/`: build output directory
