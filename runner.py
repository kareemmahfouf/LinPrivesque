import os
import importlib


def run_all():
    raw_files = os.listdir("modules")        
    file_list = [] 
    results = {}
    for file in raw_files:
        if file.endswith(".py"):
            if file == "__init__.py" or file == "utils.py":     # we want to ignore init file
                continue
            file = os.path.splitext(file)[0]        
            file_list.append(file)
    for file in file_list:
        module = importlib.import_module(f"modules.{file}")  # dynamic import 
        if(hasattr(module, "run")):
            results[f"{file}"] = module.run()
            results[f"separation{file}"] = "--------------------------------------------------------------"
        else:
            continue
    print(results.keys())
    return results
run_all()