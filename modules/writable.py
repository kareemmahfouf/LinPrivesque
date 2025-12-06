from utils import run_cmd, parse_cmd_output, get_file_owner
from rich import print
def run():

    # Relevant world-writable directories
    skip_prefixes = ["/proc", "/sys", "/run", "/snap", "/dev/pts"]
    world_writable_dirs = []
    raw_dirs = run_cmd("find / -type d -perm -0002 2>/dev/null")
    dirs = parse_cmd_output(raw_dirs)
    for dir in dirs:
        if any(dir.startswith(prefix) for prefix in skip_prefixes):
            continue
        world_writable_dirs.append(dir)


    # World-writable files in relevant sys dirs
    world_writable_files = {}
    important_dirs = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/etc/systemd", "/etc/init.d"]
    for dir in important_dirs:
        raw_files = run_cmd(f"find {dir} -type f -perm -0002 2>/dev/null")
        files = parse_cmd_output(raw_files)
        world_writable_files[dir] = files
    
    # Writable root-owned files in relevant sys dirs
    world_writable_root_owned_files = {}
    for dir, files in world_writable_files.items():
        world_writable_root_owned_files[dir] = []
        for file in files:
            fowner = get_file_owner(file) 
            if fowner and fowner == "root":
                world_writable_root_owned_files[dir].append(file)
    result = {
        "info": {
            "world_writable_dirs": world_writable_dirs,
            "world_writable_files": world_writable_files,
            "world_writable_root_owned_files": world_writable_root_owned_files
        },
        "risks": []
    }

    # RISKS 

    # world-writable dirs
    for d in world_writable_dirs:
        if d in ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]:
            result["risks"].append(f"CRITICAL: Core directory {d} is world-writable - system is fully compromiseable")
        else:
            result["risks"].append(f"World-writable directory found: {d}")

    # world-writable root owned files
    for dir, files in world_writable_root_owned_files.items():
        for f in files:
            result["risks"].append(f"Root-owned file {f} is world-writable - privilege escalation possible")

    # writable file inside security-sensitive dir
    for dir, files in world_writable_files.items():
        if "systemd" in dir or "init.d" in dir:
            for f in files:
                result["risks"].append(f"Startup script {f} is world-writable — attackers can maintain persistence.")

    return result
