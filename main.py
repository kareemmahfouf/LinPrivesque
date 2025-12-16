import runner
from rich import print
from rich.prompt import Prompt
from rich.console import Console
from rich.style import Style
import time

__version__ = "1.0.0"

def main():

    message1 = rf"""#################################################################################################
## _____      _            _______           _                                                 ##
## |_   _|    (_)          |_   __ \         (_)                                               ##
##   | |      __   _ .--.    | |__) |_ .--.  __  _   __  .---.  .--.   .--. _  __   _   .---.  ##
##   | |   _ [  | [ `.-. |   |  ___/[ `/'`\][  |[ \ [  ]/ /__\\( (`\]/ /'`\' ][  | | | / /__\\ ##
##  _| |__/ | | |  | | | |  _| |_    | |     | | \ \/ / | \__., `'.'.| \__/ |  | \_/ |,| \__., ##
## |________|[___][___||__]|_____|  [___]   [___] \__/   '.__.'[\__) )\__.; |  '.__.'_/ '.__.' ##
##                                                                        |__]                 ##
##                                                                                             ##
#################################################################################################{"\n"}"""
    console = Console()
    message2 = f"Welcome to LinPrivesque - A Linux Privilege Escalation Enumeration Tool With Built-In Risk Analysis\nVersion: {__version__}\n\n"
    for char in message1:
        console.print(char, end="")
        time.sleep(0.0005)
    
    for char in message2:
        console.print(char, end="", style="green1")
        time.sleep(0.015)

    message3 = "Enter 'Y' if you would like to run LinPrivesque on your machine: "

    while True:
        for char in message3:
            console.print(char, end="", style="green1")
            time.sleep(0.015)
        run_tool = console.input("").strip().capitalize()
        if run_tool:
            break

    if run_tool and run_tool=='Y':
        with console.status("Running LinPrivesque on your machine...\n", spinner="dots"):
            results = runner.run_all()
            console.print(results)
    else:
        console.print("Goodbye.", style="green1")
        exit()

if __name__ == "__main__":
    main()