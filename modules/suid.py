from utils import run_cmd, parse_cmd_output, is_writable, get_file_owner, GTFO_BINS


def run():

    # initialise lists of potentially exploitable binaries
    all_suid = []
    gtfo_suid = []
    writable_suid = []
    root_owned_suid = []
    raw_suid = run_cmd("find / -perm -4000 -type f 2>/dev/null")
    paths = parse_cmd_output(raw_suid)

    # iterate through each bin to build up lists
    for path in paths:
        binary = path.split("/")[-1]
        if path not in all_suid:
            all_suid.append(path)
        if binary in GTFO_BINS:
            gtfo_suid.append(path)
        if is_writable(path):
            writable_suid.append(path)
        if get_file_owner(path) == "root":
            root_owned_suid.append(path)
    
    result = {
        "info": {
            "all_suid_bins": all_suid,
            "gtfo_suid_bins": gtfo_suid,
            "writable_suid_bins": writable_suid,
            "root_owned_suid_bins": root_owned_suid
        },
        "risks": []
    }

    # RISKS

    # writable
    for writable in writable_suid:
        result["risks"].append(f"Writable SUID binary detected: {writable} — could edit it to gain root privileges")

    # non root-owned
    for root in root_owned_suid:
        gtfobinary = root.split("/")[-1] 
        if gtfobinary in GTFO_BINS:
            result["risks"].append(f"SUID binary owned by root: {root} — may allow direct root privilege escalation")

    # gtfo bins suid
    for gtfobin in gtfo_suid:
        result["risks"].append(f"SUID binary {gtfobin} is in GTFOBins — known privilege escalation technique available")

    return result
