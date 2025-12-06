from utils import run_cmd, parse_cmd_output

def run():

    dangerous_groups = {
    "sudo": "Full root escalation possible",
    "adm": "Can read system logs, may leak sensitive information",
    "docker": "Docker group members can escalate to root",
    "lxd": "LXD group members can escalate to root",
    "disk": "Can read/write raw disk"
    }

    # kernel
    kernel = run_cmd("uname -r")
    
    # architecture
    arch = run_cmd("uname -m")

    # distro info
    raw_distro_info = run_cmd("cat /etc/os-release")
    os_lines = parse_cmd_output(raw_distro_info)
    distro = ""
    distro_version = ""
    for line in os_lines:
        if line.startswith("NAME="):
            distro = line.split("=", 1)[1].strip('"')
        if line.startswith("VERSION_ID="):
            distro_version = line.split("=", 1)[1].strip('"')
    
    # hostname, user, groups
    hostname = run_cmd("hostname")
    user = run_cmd("whoami")
    groups = run_cmd("groups").split()
    
    # path, uptime
    path = run_cmd("echo $PATH")
    uptime = run_cmd("uptime -p")

    result = {
        "info": {
            "kernel": kernel,
            "architecture": arch,
            "os_name": distro,
            "os_version": distro_version,
            "hostname": hostname,
            "user": user,
            "groups": groups,
            "path": path, 
            "uptime": uptime
        },
        "risks":[]     # empty for now, add in later
    }

    # RISKS
    for group in groups:
        if group in dangerous_groups:
            result["risks"].append(f"GROUPS - user in {group} - {dangerous_groups[group]}")

    return result

