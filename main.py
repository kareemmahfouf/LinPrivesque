import runner

__version__ = "1.0.0"

def main():

    message = rf"""  _____      _            _______           _                                                
 |_   _|    (_)          |_   __ \         (_)                                               
   | |      __   _ .--.    | |__) |_ .--.  __  _   __  .---.  .--.   .--. _  __   _   .---.  
   | |   _ [  | [ `.-. |   |  ___/[ `/'`\][  |[ \ [  ]/ /__\\( (`\]/ /'`\' ][  | | | / /__\\ 
  _| |__/ | | |  | | | |  _| |_    | |     | | \ \/ / | \__., `'.'.| \__/ |  | \_/ |,| \__., 
 |________|[___][___||__]|_____|  [___]   [___] \__/   '.__.'[\__) )\__.; |  '.__.'_/ '.__.' 
                                                                        |__]  
                                                                                       
 Welcome to LinPrivesque - A Linux Privilege Escalation Enumeration Tool With Built-In Risk Analysis
 Version: {__version__}
"""
    print(message)

    # while True:
    #     run_tool = input("Enter 'Y' if you would like to run LinPrevesque on your machine: ")
    #     if run_tool:
    #         break

    # if run_tool and run_tool=='Y':
    #     results = runner.run_all()
    #     print(results)
    # else:
    #     print("Goodbye.")
    #     exit()
    print(runner.run_all())
    # ADD: coloured cli, loading bar, selection for different modules to run, email report?, convenient and aesthetic results output

if __name__ == "__main__":
    main()