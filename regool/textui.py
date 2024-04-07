from rich.console import Console
from rich.table import Table
console = Console()
 
class Tabela():
    def __init__(self):
        self.table_ao = Table(title="Address Objects to create")
        self.table_ao.add_column("Device", justify="right", style="cyan", no_wrap=True)
        self.table_ao.add_column("Name", justify="center", style="magenta")
        self.table_ao.add_column("Content", justify="left", style="green")
        self.table_ao.add_column("Type", justify="center", style="green")
 
        self.table_ag = Table(title="Address Groups to create")
        self.table_ag.add_column("Device", justify="right", style="cyan", no_wrap=True)
        self.table_ag.add_column("Name", justify="center", style="magenta")
        self.table_ag.add_column("Addresses", justify="left", style="green")
       
        self.table_sr = Table(title="Security rules to create")
        self.table_sr.add_column("Device", justify="right", style="cyan", no_wrap=True)
        self.table_sr.add_column("Name", justify="center", style="magenta")
        self.table_sr.add_column("From Zone", justify="left", style="green")
        self.table_sr.add_column("To Zone", justify="left", style="green")
        self.table_sr.add_column("Source", justify="left", style="green")
        self.table_sr.add_column("Destination", justify="left", style="green")
        self.table_sr.add_column("Service", justify="left", style="green")
        self.table_sr.add_column("Application", justify="left", style="green")
 
    def add_ao(self, dev, name, ip, type):
        self.table_ao.add_row(dev, name, ip, type)
 
    def add_ag(self, dev, name, addr):
        self.table_ag.add_row(dev, name, ', '.join(addr))
 
    def add_sr(self, rule):
        src = rule['source']
        self.table_sr.add_row(rule['dev'],  rule['name'], rule['fromzone'], rule['tozone'], ', '.join(rule['source']), ', '.join(rule['destination']), ', '.join(rule['service']), ', '.join(rule['application']))
 
    def print_ao(self):
        console.print(self.table_ao)
 
    def print_ag(self):
        console.print(self.table_ag)
 
    def print_sr(self):
        console.print(self.table_sr)
 
def main():
    tabela = Tabela()
    tabela.add_ao("FW-01", "srv1-10.1.1.5", "10.1.1.5", "IP")
    tabela.add_ao("FW-01", "srv2-10.1.1.6", "server1.sys.frm.com", "FQDN")
    tabela.print_ao()
    adr_list = ["1.1.1.1", "2.2.2.2"]
    tabela.add_ag("FW-01","agroup-01", adr_list)
    tabela.print_ag()
    rule = {}
    rule['fromzone'] = "INSIDE"
    rule['tozone'] = "OUTSIDE"
    rule['source'] = ['10.1.2.3', '10.1.4.5']
    rule['destination'] = ['172.2.2.2', '172.9.8.9']
    rule['service'] = ['80', '443']
    rule['application'] = ['web-browsing', 'ssl']
    rule['name'] = 't722-test-rule'
    rule['dev'] = 'FW-01'
    tabela.add_sr(rule)
    tabela.print_sr()
 
if __name__ == "__main__":
    main()