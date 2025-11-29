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



   return {"info": {
      "all_entries": all_entries,
      "writable_entries": writable_entries,
      "nonexistent_entries": nonexistent_entries,
      "empty_entries": empty_entries,
      "dangerous_order": dangerous_order
   }, 
   "risks": []
   }

