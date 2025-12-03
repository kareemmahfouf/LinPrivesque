from utils import run_cmd, parse_cmd_output

# collect network interfaces
network_interfaces = []
lines = parse_cmd_output(run_cmd("ip -i link show"))
for line in lines:
    start = line[0]
    if start.isnumeric():
        network_interfaces.append(line.split(":", maxsplit=2)[1].strip())

# collect ip addresses per interface
ip_addresses = {}
raw_ip = run_cmd("ip -o addr show")
IP_lines = parse_cmd_output(raw_ip)

for interface in network_interfaces:
    if interface not in ip_addresses:
        ip_addresses[interface] = {
            "ipv4": [],
            "ipv6": []
        }

    for line in IP_lines:
        parts = line.split()
        if interface != parts[1]:
            continue
        family = parts[2]
        address = parts[3]
        if family == "inet":
            ip_addresses[interface]["ipv4"].append(address)
        elif family == "inet6": 
            ip_addresses[interface]["ipv6"].append(address)

# extract routes
raw_routes = run_cmd("ip route")
route_lines = parse_cmd_output(raw_routes)
route_info = {
    "default_route": None,
    "routes": []
}
for line in route_lines:
    route_parts = line.split()
    if line.startswith("default"):
        gateway = route_parts[2]
        route_interface = route_parts[4]
        route_info["default_route"] = {
            "gateway": gateway,
            "interface": route_interface
        }
        continue
    
    subnet = route_parts[0]
    dev_index = route_parts.index("dev")
    route_interface = route_parts[dev_index + 1]
    route_info["routes"].append({
        "subnet": subnet,
        "interface": route_interface
    })

# extract active connections
raw_connects = run_cmd("ss -tulpn 2>/dev/null")
listening_lines = []
for line in parse_cmd_output(raw_connects):
    if "LISTEN" in line:
        listening_lines.append(line.strip())

for line in listening_lines:
    listening_parts = line.split()
    print(listening_parts)