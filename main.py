import sys
import requests
import time
from colorama import init, Fore
from scapy.all import ARP, Ether, srp
import dns.resolver

init()

green_text = """
                 ██████╗██╗   ██╗██████╗ ██╗  ██╗███████╗██████╗ ███████╗███╗   ██╗██╗███████╗███████╗
                ██╔════╝╚██╗ ██╔╝██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝
                ██║      ╚████╔╝ ██████╔╝███████║█████╗  ██████╔╝███████╗██╔██╗ ██║██║█████╗  █████╗ 
                ██║       ╚██╔╝  ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝ 
                ╚██████╗   ██║   ██║     ██║  ██║███████╗██║  ██║███████║██║ ╚████║██║██║     ██║
                 ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ██╔╝╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝"""
credit = "                                  ------  [+] Tool by @Eyad156 or Driplay -------"
print(Fore.GREEN, green_text)
print(Fore.LIGHTBLUE_EX, credit)

CHECK_INTERNET = requests.get('http://www.google.com/')
if CHECK_INTERNET.status_code == 200:
    print(Fore.LIGHTGREEN_EX + "# Internet : Active")
else:
    print(Fore.RED + "!! No Internet Exiting in 10 seconds ): " + '\n')
    time.sleep(10)
    sys.exit()

print(Fore.LIGHTYELLOW_EX + """1. Get All connected on Wifi
2. Subdomain detector
3. XSS Scanner (not implemented)
4. Get Location By IP Address (not implemented)""")
CHOOSE = input(Fore.CYAN + 'Choice (1 or 2 or 3 or 4) > ')

def scan_network(ip_range):
    print(Fore.GREEN + "Note: Install Npcap first ):")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

subdomains = [
    "www", "mail", "ftp", "webmail", "remote", "blog", "webdisk", "ns1", "ns2", "cpanel", "whm", "autodiscover",
    "autoconfig", "m", "mobile", "imap", "pop", "smtp", "test", "sandbox", "dev", "staging", "api", "beta"
]

def check_subdomains(domain):
    found_subdomains = []
    for subdomain in subdomains:
        subdomain_url = f'{subdomain}.{domain}'
        try:
            answers = dns.resolver.resolve(subdomain_url, 'A')
            for _ in answers:
                found_subdomains.append(subdomain_url)
                print(Fore.GREEN + f'[+] Found Subdomain -> {subdomain_url}')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
            pass
        except Exception as e:
            print(Fore.RED + f"Error checking {subdomain_url}: {e}")

    return found_subdomains

if CHOOSE == '1':
    ip_range = "192.168.1.1/24"
    devices = scan_network(ip_range)
    print(Fore.WHITE + "Connected devices:")
    for device in devices:
        print(Fore.LIGHTMAGENTA_EX + f"IP -> {device['ip']} - MAC: {device['mac']}")

elif CHOOSE == '2':
    domain = input("Enter the domain to scan for subdomains (e.g., example.com): ")
    found_subdomains = check_subdomains(domain)

    if found_subdomains:
        print("\nFound subdomains:")
        for sub in found_subdomains:
            print(sub)
    else:
        print("No subdomains found.")

else:
    print(Fore.RED + "Invalid choice or not implemented yet.")
