from utils import run_cmd, parse_cmd_output

def run():
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

    # listening ports
    listening = []
    raw_listening = run_cmd("ss -tulpn 2>/dev/null")
    listening_lines = []
    for line in parse_cmd_output(raw_listening):
        if "LISTEN" in line:
            listening_lines.append(line.strip())

    for line in listening_lines:
        listening_parts = line.split()
        protocol = listening_parts[0]
        state = listening_parts[1]
        local = listening_parts[4]
        remote = listening_parts[5]
        entry = {
            "protocol": protocol,
            "state": state,
            "local": local,
            "remote": remote,
        }
        if len(listening_parts) > 6 and "users" in listening_parts[6]:
            process_info = listening_parts[-1]
            process_name = process_info.split("(")[2].split(",")[0].strip('"')
            pid = process_info.split("pid=")[1].split(",")[0]
            entry["process"] = process_name
            entry["pid"] = pid
        listening.append(entry)

    # all active connections
    active_connects = []
    raw_connects = run_cmd("ss -tunp")
    connects_lines = []
    for line in parse_cmd_output(raw_connects)[1:]:
        connects_lines.append(line.strip())

    for line in connects_lines:
        connects_parts = line.split()
        connects_protocol = connects_parts[0]
        connects_state = connects_parts[1]
        local_addr = connects_parts[4]
        remote_addr = connects_parts[5]
        connects_entry = {
            "protocol": connects_protocol,
            "state": connects_state,
            "local": local_addr,
            "remote": remote_addr
        }

        if "users:(" in line:
            connects_process_name = connects_parts[-1].split("(")[2].split(",")[0].strip('"')
            connects_pid = connects_parts[-1].split("pid=")[1].split(",")[0]
            connects_entry["process"] = connects_process_name
            connects_entry["pid"] = connects_pid

        active_connects.append(connects_entry)

    # parse /etc/resolv.conf for dns info
    raw_resolv = run_cmd("cat /etc/resolv.conf")
    resolv = []
    resolv_lines = parse_cmd_output(raw_resolv)
    for line in resolv_lines:
        if line and not line.startswith("#"):
            resolv.append(line)
    nameservers = []
    search_domains = []
    options = []
    for line in resolv:
        split_line = line.split()
        match split_line[0]:
            case "nameserver":
                nameservers.append(split_line[1])
            case "options": 
                options.extend(split_line[1:])
            case "search":
                search_domains.extend(split_line[1:])
    dns_info = {
        "nameservers": nameservers,
        "search_domains": search_domains,
        "options": options
    }

    # build arp table
    arp = []
    raw_arp = run_cmd("ip neigh")
    arp_lines = parse_cmd_output(raw_arp)
    for line in arp_lines:
        arp_entry = {
            "ip": line.split()[0],
            "mac": line.split()[4],
            "interface": line.split()[2],
            "state": line.split()[-1]
        }
        arp.append(arp_entry)

    return {
        "info": {
            "interfaces": network_interfaces,
            "ip_addresses": ip_addresses,
            "routes": route_info,
            "listening_services": listening,
            "active_connections": active_connects,
            "dns_info": dns_info,
            "arp_table": arp
        },
        "risks": []
    }
run()