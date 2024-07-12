from blessed import Terminal
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()
term = Terminal()



def printError(message):
    print(term.bold_white_on_red(f"ERROR: {message}"))

def printInfo(message):
    print(term.bold_blue_on_white(f"INFO: {message}"))

def printWarn(message):
    print(term.bold_black_on_yellow(f"WARNING: {message}"))

def printSuccess(message):
    print(term.bold_black_on_green(f"SUCCESS: {message}"))

def getTablePrint(title):
    table = Table(title=title)
    return table

def printPartitionsTable(partitionTable):
    table = getTablePrint("Partitions Found")
    table.add_column("Address",  style="cyan", no_wrap=True)
    table.add_column("Description",  style="magenta")
    table.add_column("Size",  style="green")
    for partition in partitionTable:
        table.add_row(f"{partition.addr}",f"{partition.desc}", f"{partition.len * 512}")
    console.print(table)