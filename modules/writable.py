from utils import run_cmd, parse_cmd_output, get_file_owner

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
    return{
        "info": {
            "world_writable_dirs": world_writable_dirs,
            "world_writable_files": world_writable_files,
            "world_writable_root_owned_files": world_writable_root_owned_files
        },
        "risks": []
    }

