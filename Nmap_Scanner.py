import nmap


def TCPSCAN(ip):
    print("****"*10)
    print("Scanning starts now:")
    scanner = nmap.PortScanner()
    scanner.scan(ip,'1-1024',arguments='-n -sS')
    print("Scanning info --- :",scanner.scaninfo())
    print("Device status:",(scanner[ip].state()))
    for proto in scanner[ip].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
         lport = scanner[ip][proto].keys()
         sorted(lport)
         for port in lport:
             print ('port : %s\tstate : %s' % (port, scanner[ip][proto][port]['state']))
    print("****"*10)

def UDPSCAN(ip):
    print("****"*10)
    print("Scanning starts now:")
    scanner = nmap.PortScanner()
    scanner.scan(ip,'1-1024',arguments='-n -sU')
    print("Scanning info --- :",scanner.scaninfo())
    print("Device status:",(scanner[ip].state()))
    for proto in scanner[ip].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
         lport = scanner[ip][proto].keys()
         sorted(lport)
         for port in lport:
             print ('port : %s\tstate : %s' % (port, scanner[ip][proto][port]['state']))
    print("****"*10)

def FULLSCAN(ip):
    print("****"*10)
    print("Scanning starts now:")
    scanner = nmap.PortScanner()
    scanner.scan(ip,'1-1024',arguments='-sS -sV -O ')
    print("Scanning info --- :",scanner.scaninfo())
    print("Device status:",(scanner[ip].state()))
    for proto in scanner[ip].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
         lport = scanner[ip][proto].keys()
         sorted(lport)
         for port in lport:
             print ('port : %s\tstate : %s\tservice : %s' % (port, scanner[ip][proto][port]['state'], scanner[ip][proto][port]['name']))
         print ('OS Detection: %s' %(scanner[ip]['osmatch'][1]))
    print("****"*10)