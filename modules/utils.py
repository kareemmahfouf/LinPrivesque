import subprocess
import os 
import pwd 

GTFO_BINS = [                       # common gtfobins, NOT ALL of them
    "bash", "sh", "dash", "zsh",
    "python", "python3", "perl", "ruby", "lua", "php",
    "nmap", "find", "awk", "sed",
    "less", "more", "man", "vi", "vim",
    "tar", "cp", "mv", "tee",
    "curl", "wget",
    "rsync", "socat", "openssl",
    "env",
]

def run_cmd(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except:
        return ""


def parse_cmd_output(output):
    lines = output.split("\n")
    cleaned_lines_list = []
    for line in lines:
        if line == "":
            continue
        cleaned_lines_list.append(line.strip())
    return cleaned_lines_list

def is_writable(fpath):
    try:
        return os.access(fpath, os.W_OK)
    except:
        return False
    
def is_executable(fpath):
    try:
        return os.access(fpath, os.X_OK)
    except:
        return False
    
def get_file_owner(fpath):
    try: 
        stats = os.stat(fpath)
        return pwd.getpwuid(stats.st_uid).pw_name
    except:
        return None
    