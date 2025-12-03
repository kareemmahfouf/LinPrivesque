from utils import run_cmd

def run():
    kernel_vuln_ranges = {
        "DirtyCow": {"minimum": (2, 6, 22), "maximum": (4, 8)},
        "DirtyPipe": {"minimum": (5, 8), "maximum": (5, 16, 11)},
        "OverlayFS": {"minimum": (3, 13), "maximum": (5, 4)}
    }

    def normalise_tuple(tuple, target_length):
        return tuple + (0,) * (target_length - len(tuple))

    raw_kernel = run_cmd("uname -r")
    parsed_kernel = tuple(map(int, normalise_tuple(tuple(raw_kernel.split("-")[0].split(".")), 3)))
    aslr = int(run_cmd("cat /proc/sys/kernel/randomize_va_space"))
    ptrace = int(run_cmd("cat /proc/sys/kernel/yama/ptrace_scope"))


    kernel_vulns = []
    for vuln, ranges in kernel_vuln_ranges.items():
        minimum = normalise_tuple(ranges["minimum"], 3)
        maximum = normalise_tuple(ranges["maximum"], 3)
        if minimum <= parsed_kernel <= maximum:
            kernel_vulns.append(vuln)

    if not kernel_vulns:
        kernel_vulns.append("No known vulnerabilities related to current kernel version")

    match aslr:
        case 0:
            aslr_status = "ASLR disabled"
        case 1:
            aslr_status = "Partial ASLR"
        case 2:
            aslr_status = "Full ASLR"

    match ptrace:
        case 0:
            ptrace_status = "No restrictions"
        case 1:
            ptrace_status = "Restricted (default)"
        case 2:
            ptrace_status = "Admin-only"
        case 3:
            ptrace_status = "No attach"
        case _:
            ptrace_status = "Unknown value"
            
    return {
        "info": {
            "raw_kernel_info": raw_kernel,
            "vulnerabilities_searched_for": list(kernel_vuln_ranges),
            "vulnerabilities_found": kernel_vulns,
            "ASLR_status": aslr_status,
            "ptrace_status": ptrace_status
        },
        "risks": []
    }
