from blessed import Terminal
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()
term = Terminal()


def printError(message):
    text = Text(f"ERROR: {message}", style="bold white on red")
    console.print(text)    
    
def printInfo(message):
     text = Text(f"INFO: {message}", style="bold blue on white")
     console.print(text)
     
def printWarn(message):
    text = Text(f"WARNING: {message}", style="bold black on yellow")
    console.print(text)
    
def printSuccess(message):
    text = Text(f"SUCCESS: {message}", style="bold black on green")
    console.print(text)

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