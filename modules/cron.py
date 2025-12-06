from utils import run_cmd, is_writable, get_file_owner, parse_cmd_output
import os

def run():

    # nested function to parse later cron commands
    def parse_cron_cmd(schedule, cmd_string):
        path_risk = False
        does_exist = False
        writable = False
        file_owner = None
        interpreter = None
        


        parts = cmd_string.split()
        if not parts:
            return {
                "schedule": schedule,
                "command": cmd_string,
                "binary": None,
                "absolute": False,
                "exists": False,
                "writable": False,
                "owner": None,
                "interpreter": None,
                "path_hijack_risk": True
            }

        first_token = parts[0]
        is_absolute = first_token.startswith("/")

        if is_absolute:
            does_exist = os.path.exists(first_token)
            if not does_exist:
                path_risk = True

        else:
            path_risk = True

        if does_exist:
            writable = is_writable(first_token)
            file_owner = get_file_owner(first_token)
            
        

        dangerous_interpreters = ["bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "php", "lua", "nc", "socat", "wget", "curl"]
        if first_token.split("/")[-1] in dangerous_interpreters:
            interpreter = first_token.split("/")[-1]


        return {
            "schedule": schedule,
            "command": cmd_string,
            "binary": first_token,
            "absolute": is_absolute,
            "exists": does_exist,
            "writable": writable,
            "owner": file_owner,
            "interpreter": interpreter,
            "path_hijack_risk": path_risk
            }



    # system cron info
    system_cron_dirs = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d"]

    system_cron_info = {}

    for dir in system_cron_dirs:
        dir_info = {
            "files": [],
            "writable_files": [],
            "non_root_owned_files": []
        }
        
        if not os.path.exists(dir):
            system_cron_info[dir] = dir_info
            continue
        try:
            files = os.listdir(dir)
        except:
            system_cron_info[dir] = dir_info
            continue

        for file in files:
            fpath = os.path.join(dir, file)
            dir_info["files"].append(fpath)
            if is_writable(fpath):
                dir_info["writable_files"].append(fpath)
            if get_file_owner(fpath) and get_file_owner(fpath) != "root":
                dir_info["non_root_owned_files"].append(fpath)
        system_cron_info[dir] = dir_info
    
    # user cron info
    raw_crontab = run_cmd("crontab -l 2>/dev/null")
    risks = []
    user_cron_info = {
        "crontab_exists": False,
        "environment_vars": {},
        "jobs": []
    }
    if raw_crontab:
        user_cron_info["crontab_exists"] = True
    
        user_cron_lines = parse_cmd_output(raw_crontab)
        for line in user_cron_lines:

            # comments
            if line.startswith("#") or not line:
                continue

            # special jobs
            if line.startswith("@"):
                schedule, command = line.split(" ", 1)
                parsed_cron = parse_cron_cmd(schedule, command)
                user_cron_info["jobs"].append(parsed_cron)
                continue
            
            # environment variables
            if "=" in line and not line[0].isdigit():
                key, value = line.split("=", 1)      
                user_cron_info["environment_vars"][key] = value
                if key == "PATH":
                    entries = value.split(":")
                    for entry in entries:
                        expanded = os.path.expandvars(entry)                       
                        if not os.path.exists(expanded):
                            risks.append(f"Nonexistent PATH entry {entry} in crontab - bad actor can create it to hijack execution")
                        else:
                            if is_writable(expanded):
                                risks.append(f"Writable PATH directory {expanded} in crontab - bad actor can hijack cron job execution")
                continue
            
            # parse generic cron jobs
            line_items = line.split()
            if len(line_items) >= 6:
                schedule = " ".join(line_items[:5])
                command = " ".join(line_items[5:])
                parsed_cron = parse_cron_cmd(schedule, command)
                user_cron_info["jobs"].append(parsed_cron) 
    
    result = {
        "info": {
            "system_cron": system_cron_info,
            "user_cron": user_cron_info
        },
        "risks": []
    }
        
    # RISKS

    # writable cron files
    for dir, info in system_cron_info.items():
        for f in info["writable_files"]:
            result["risks"].append(f"CRITICAL: System cron file {f} is world-writable - bad actor can execute arbitrary commands as root")
    
    # sys cron file non root owned
        for f in info["non_root_owned_files"]:
            result["risks"].append(f"CRITICAL: System cron file {f} is not root-owned - privilege escalation possible")

    # cron dir is writable
    for dir in system_cron_info:
        if is_writable(dir):
            result["risks"].append(f"CRITICAL: Cron directory {dir} is writable - bad actor can add persistent root-performed jobs")

    # cron job uses relative path
    for job in user_cron_info["jobs"]:
        if not job["absolute"]:
            result["risks"].append(f"Cron job {job['command']} uses a relative path {job['binary']} - vulnerable to PATH hijacking")

    # collect other risks
    for warning in risks:
        result["risks"].append(warning)

    return result

