import socket
from tqdm import tqdm
import threading 
import nmap

class PortScanner:

    def __init__(self, target_host, port_range ='0' ,threads=40):
        self.target_host = target_host
        self.port_range = port_range 

        #user input port scan range 
        self.port_range = input("[+] Enter port range you would like to scan: ")
        self.prange = '0-' + self.port_range

    def syn_scan(self):
        try:
            nm = nmap.PortScanner()
          
            result = nm.scan(self.target_host, self.prange, arguments='-sS -T3')
            cmd = result['nmap']['command_line']
            host = list(result['scan'].keys())[0]

            open_ports = result['scan'][host]['tcp']
            print('scan type: SYN scan')
            print(f"[+] scan command {cmd}")
            for i in open_ports.keys():
                print(f"[+] Service Found: {open_ports[i]['name']} on port {i}. Port state: {open_ports[i]['state']}")
            #ports = nm.scan(self.target_host, arguments='-F -sS -T5')['scan'][self.target_host]['tcp'].keys()nm 
            print(f"[+] Scan complete: Mac Address {result['scan'][host]['addresses']['mac']}")

        except socket.error:
            pass
    
    def connect_scan(self):
        #fast scan
        nm = nmap.PortScanner()
        ports = nm.scan(self.target_host, self.prange, arguments=' -sS -T5')['nmap']['scaninfo']['tcp']['services']
        #return open port number 
        return ports

    def service_scan(self, ports):
        nm = nmap.PortScanner()
        # scan service using default scripts and version detection
        service_result = nm.scan(self.target_host, ports, arguments='-sV -sC -vv -T5')
        #print nmap results
        cmd = service_result['nmap']['command_line']
        ip = list(service_result['scan'].keys())[0]
        print(ip)
        service_result = service_result['scan'][ip]['tcp']

        

        print(f"[+] scan command {cmd}")
        
        port_count = len(list(service_result.keys()))
        print(f"[+] Total found ports: {port_count} ")
        for port in service_result.keys():
            print(f"\n[+] Service on port {port}:")
            for key,value in service_result[port].items():
              
                    ##printt out found open ports and service information
                print(f" --- {key}:{value}")
            #print out port numbers and service information
            print(f'[+] Service on port {port}:{service_result[port]}')


    def fast_ack_scan(self):
        nm = nmap.PortScanner()
        #does an ack scan plus only top ports in a range 
        result = nm.scan(self.target_host, self.port_range, arguments=f'-sA -T5 --top-ports {self.port_range}')
        cmd = result['nmap']['command_line']
        host = list(result['scan'].keys())[0]

        open_ports = result['scan'][host]['tcp']

        print('scan type: ACK scan')
        print(f"[+] scan command {cmd}")
        print(f"[+] Scan initiated on: {result['nmap']['scanstats']['timestr']}")

        for i in open_ports.keys():
            print(f"[+] Service Found: {open_ports[i]['name']} on port {i}. Port state: {open_ports[i]['state']}")

        print(f"[+] Scan complete: Mac Address {result['scan'][host]['addresses']['mac']}")
    def scan_type(self):
        scan_tech = ['Stealth SYN/Half-open scan', 'Connect scan', 'Fast TCP ACK scan']
    
        print('scan options: \n')
        for i in range(len(scan_tech)):
            print(f"{i+1}. {scan_tech[i]}")

        #check if user has selected scan from list if not loop again
        loop = True
        while True:
            scan_op = input("[+] Enter scan option you would like to use: ")
            if int(scan_op) > len(scan_tech):
                print("Please select a scan options from list displayed!")
                continue
        
            break
        return scan_op

    def run(self, scan_op):
        try:
            
            print(f"Scanning {self.target_host}\n")
            scan_op = int(scan_op)

            #choose scan based on user options
            if scan_op == 1:
                #stealth scan check if ports are open
                ports = self.syn_scan()
            elif scan_op == 2:
                ports = self.connect_scan()
                self.service_scan(ports)
            elif scan_op == 3:
                self.fast_ack_scan()
            elif scan_op == 'exit':
                exit
           
            
        except:
            pass

if __name__ == "__main__":

    #target= input("[+]     Please enter host to scan: ")
    
    while True:
        scanner = PortScanner("192.168.204.7") # change ip to scan target
        #scanner = PortScanner("127.0.0.1") 
        scan_op = scanner.scan_type()
        scanner.run(scan_op)