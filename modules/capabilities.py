from utils import run_cmd, parse_cmd_output, is_writable, get_file_owner
import os

DANGER_CAPS = [
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_dac_read_search",
    "cap_chown",
    "cap_fowner",
    "cap_fsetid",
]
def run():
    
    raw_capabilities = run_cmd("getcap -r / 2>/dev/null")
    lines = parse_cmd_output(raw_capabilities)
    all_capabilities = []
    dangerous_capabilites = []
    writable_capability_bins = []
    writable_capability_dirs = []
    non_root_owned_capability_bins = []
    for line in lines:

        path, capability = line.split(maxsplit=1)
        capabilities = []
        cleaned_caps = []
        if len(capability.split(",")) > 1:
            for cap in capability.strip().split(","):
                if cap not in capabilities:
                    capabilities.append(cap)
        else:
            if capability not in capabilities:
                capabilities.append(capability)
        for cap in capabilities:
            if "=" in cap:
                cap = cap.split("=")[0]                
                cleaned_caps.append(cap)
            else:
                cleaned_caps.append(cap)

        entry = {
            "path": path,
            "capabilities": cleaned_caps,
            "writable_dir": is_writable(os.path.dirname(path)),
            "writable_binary": is_writable(path),
            "owner": get_file_owner(path)
        }
        all_capabilities.append(entry)
        if entry["writable_binary"]:
            writable_capability_bins.append(entry)
        if entry["writable_dir"]:
            writable_capability_dirs.append(entry)
        if entry["owner"] and entry["owner"] != "root": 
            non_root_owned_capability_bins.append(entry)
        for cap in entry["capabilities"]:
            if cap in DANGER_CAPS:
                dangerous_capabilites.append(entry)
                break

    return_info = {
        "info": {
        "all_capabilities": all_capabilities,
        "dangerous_binaries": dangerous_capabilites,
        "writable_capability_binaries": writable_capability_bins,
        "writable_capability_dirs": writable_capability_dirs,
        "non_root_owned_capability_binaries": non_root_owned_capability_bins
        },
        "risks": []
    }

    # RISKS
    # dangerous caps assigned to any binary
    for cap_entry in dangerous_capabilites:
        return_info["risks"].append(f"Binary {cap_entry['path']} has dangerous capabilities: {cap_entry['capabilities']}")

    # capability binary is writable
    for writable in writable_capability_bins:
        return_info["risks"].append(f"Capability binary {writable['path']} is writable — bad actor can replace it to gain root")
    
    # capability binary is in a writable directory
    for writable_dir in writable_capability_dirs:
        dir_path = os.path.dirname(writable_dir["path"])
        return_info["risks"].append(f"Directory {dir_path} containing capability binary {writable_dir['path']} is writable — very high privilege escalation risk.")

    # capability binary non root-owned
    for non_root in non_root_owned_capability_bins:
        return_info["risks"].append(f"Capability binary {non_root['path']} is owned by {non_root['owner']}, not root — bad actor may modify or replace it.")

    return return_info
