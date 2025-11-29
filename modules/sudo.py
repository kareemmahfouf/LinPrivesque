from utils import run_cmd, parse_cmd_output, GTFO_BINS


def run():

    run_cmd("sudo -k")   # kills current sudo session, avoids faulty results with below logic
    can_sudo = False
    nopasswd = False
    potential_escapes=[]
    allowed_commands=[]
    raw_sudo = run_cmd("sudo -l -n 2>/dev/null") # suppress errors- stderr to dev/null- error returns ""
    
    # raw_sudo is empty
    if raw_sudo == "":
        groups = run_cmd("groups").split() 
        if "sudo" in groups or "wheel" in groups or "admin" in groups:   # if any are true, user can sudo but requires passwd
            can_sudo = True
            reason = "sudo rules require authentication and therefore cannot be listed"
            allowed_commands.append(reason)
            potential_escapes.append(reason)
        else:
            can_sudo = False 

        return {
            "info": {
                "can_sudo": can_sudo,
                "nopasswd": nopasswd,
                "allowed_commands": allowed_commands,
                "potential_escapes": potential_escapes,
                "raw": "" 
            },
            "risks": []
        }


    # raw_sudo is not empty
    can_sudo = True
    lines = parse_cmd_output(raw_sudo)

    for line in lines:
        # FULL SUDO CASES: 1/3 (ALL) ALL     or     (ALL:ALL) ALL
        line = line.strip()
        if line.startswith("(") and line.endswith(" ALL") and "PASSWD:" not in line and "NOPASSWD:" not in line:
            allowed_commands = ["ALL"]
            potential_escapes = ["ALL"]
            continue
        
        # FULL SUDO CASES: 2/3 (ALL) NOPASSWD: ALL   (full sudo w/o passwd)
        if "NOPASSWD:" in line and line.strip().endswith("ALL"):
            allowed_commands = ["ALL"]
            potential_escapes = ["ALL"]
            nopasswd = True
            continue

        #FULL SUDO CASES 3/3 (ALL) PASSWD: ALL    (full sudo w/ pass)
        if "PASSWD:" in line and line.strip().endswith("ALL"):
            allowed_commands = ["ALL"]
            potential_escapes = ["ALL"]
            continue

        else:
            if "NOPASSWD:" in line or "PASSWD:" in line:

                if "NOPASSWD:" in line:
                    nopasswd = True
                
                # if nopasswd all (full sudo)
                lhs, rhs = line.split(":", 1)
                if rhs.strip() == "ALL":
                    allowed_commands = ["ALL"]
                    potential_escapes = ["ALL"]
                    nopasswd = True
                    continue

                for cmd in rhs.split(","):
                    clean_cmd = cmd.strip()
                    allowed_commands.append(clean_cmd)       
                    binary = clean_cmd.split("/")[-1]
                    if binary in GTFO_BINS:
                        potential_escapes.append(clean_cmd)

    return {
        "info": {
            "can_sudo": can_sudo,
            "nopasswd": nopasswd,
            "allowed_commands": allowed_commands,
            "potential_escapes": potential_escapes,
            "raw": raw_sudo
        },
        "risks": []
    }

