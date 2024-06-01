import scapy
import scrapy
import sys
from colorama import init, Fore
import requests
import time 
import socket
from scapy.all import ARP, Ether, srp
import dns.resolver
init()
green_text = """
                 ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ ███████╗███╗   ██╗██╗███████╗███████╗
                ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝
                ██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝███████╗██╔██╗ ██║██║█████╗  █████╗ 
                ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝ 
                ╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║███████║██║ ╚████║██║██║     ██║
                 ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝"""
credit = "                                  ------  [+] Tool by @Eyad156 or Driplay -------"
print(Fore.GREEN ,green_text)
print(Fore.LIGHTBLUE_EX,credit)
CHECK_INTERNET = requests.get('http://www.google.com/')
if CHECK_INTERNET.status_code == 200:
    print(Fore.LIGHTGREEN_EX + "# Internet : Active")
else:
    print(Fore.RED + "!!No Internet Exitting in 10 seconds ):" + '\n')
    time.sleep(10)
    sys.exit()
print(Fore.LIGHTYELLOW_EX + """1. Get All connected on Wifi
2. Subdomain detector
3. Xss Scanner
4. Get Location By IP Address""")
CHOOSE = input(Fore.CYAN + 'Choice (1 or 2 or 3 or 4) > ')
if CHOOSE == '1':
    def scan_network(ip_range):
        print(Fore.GREEN + "Note :Install Wincap first ):")
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=False)[0]
        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        return devices
if CHOOSE == '2':
    subdomains = ["www", "mail", "ftp", "webmail", "remote", "blog", "webdisk", "ns1", "ns2", "cpanel", "whm", "autodiscover",
    "autoconfig", "m", "mobile", "imap", "pop", "smtp", "test", "sandbox", "dev", "staging", "api", "beta"]
    def check_subdoamins(domain):
        found_subdomains = []
        for subdomain in subdomains:
            url = f'https://{subdomain}.domain.com'
            try:
                answer = dns.resolver.reslove(f'subdomain.domain.com', "A")
                if answer:
                    found_subdomains.append(url)
                    print(Fore.GREEN + f'[+] Found Subdomain -> {url}')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
                pass
            except Exception as e:
                    print(Fore.RED + f"Error checking {subdomain}.{domain}: {e}")
                    
            return found_subdomains
if __name__ == "__main__":
    ip_range = "192.168.1.1/24"  
    devices = scan_network(ip_range)
    print(Fore.WHITE + "Connected devices:")
    for device in devices:
        print( Fore.LIGHTMAGENTA_EX + f"IP -> {device['ip']} - MAC: {device['mac']}")
        time.sleep(10)
    domain = input("Enter the domain to scan for subdomains (e.g., example.com): ")
    found_subdomains = check_subdoamins(domain)
    
    if found_subdomains:
        print("\nFound subdomains:")
        for sub in found_subdomains:
            print(sub)
    else:
        print("No subdomains found.")