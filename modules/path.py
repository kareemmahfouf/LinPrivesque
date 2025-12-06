from utils import run_cmd, is_writable
import os 


'''PATH Hijacking checks whether a privileged process (root or sudo) might call a 
   binary by name instead of full path, allowing you to replace it and hijack execution.'''

def run():
    
   # gather raw path string and parse into each entry
   path_string = run_cmd("echo $PATH")
   entries = path_string.split(":")


   all_entries = []
   writable_entries = []
   nonexistent_entries = []
   empty_entries = False
   dangerous_order = []
   trusted_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]
   for entry in entries:
      if entry not in all_entries:
         all_entries.append(entry)
      if entry == "" or entry == ".":
         empty_entries = True  
         continue
      if is_writable(entry) and entry not in writable_entries:
         writable_entries.append(entry)
      if not os.path.exists(entry):
         nonexistent_entries.append(entry)

   for entry in all_entries:
      wr_index = all_entries.index(entry)
      if entry in writable_entries:
         for dir in trusted_dirs:
            if not dir in all_entries:
               continue
            tr_index = all_entries.index(dir)
            if wr_index < tr_index:
               pair = (entry, dir)
               if pair not in dangerous_order:
                  dangerous_order.append((entry, dir))



   result = {"info": {
      "all_entries": all_entries,
      "writable_entries": writable_entries,
      "nonexistent_entries": nonexistent_entries,
      "empty_entries": empty_entries,
      "dangerous_order": dangerous_order
   }, 
   "risks": []
   }

   # RISKS

   # writable
   for writable in writable_entries:
      result["risks"].append(f"Writable PATH entry detected: {writable} — may allow binary hijacking")

   # user-level dirs before sys dirs
   for path_entry in all_entries:
    if path_entry.startswith("/home"):
        result["risks"].append(f"User-level directory early in PATH: {entry} — consider moving after system directories.")

   # writable dir before trusted dir
   for entry_pair in dangerous_order:
      result["risks"].append(f"Dangerous order - {entry_pair} - writable directory before trusted directory allows for PATH Hijacking")
   

   # empty entries
   if empty_entries:
      result["risks"].append(f"Empty PATH entry detected — '.' (current directory) is effectively in PATH.")

   # non-existent entries
   for nonexistent in nonexistent_entries:
      result["risks"].append(f"Nonexistent PATH entry: {nonexistent} — bad actor could create this path to hijack execution")

   return result
