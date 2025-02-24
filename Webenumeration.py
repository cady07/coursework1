import argparse #cadythapa
import socket
import requests
import dns.resolver
from datetime import datetime
from bs4 import BeautifulSoup

class NmapCLI:
    def __init__(self, target, port_range):
        self.target = target
        self.port_range = port_range
        self.scan_results = []

    def show_options(self):
        print("\nAvailable Options:")
        print("1. Port Scanning - Scan a range of ports on the target.")
        print("2. Directory Busting - Find directories on a web server using a wordlist.")
        print("3. Subdomain Enumeration - Find subdomains using a wordlist.")
        print("4. Version Detection - Identify the version of services running on open ports.")

    def scan_ports(self):
        print(f"Starting scan on {self.target}...")
        start_time = datetime.now()
        
        for port in range(self.port_range[0], self.port_range[1] + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    result = s.connect_ex((self.target, port))
                    if result == 0:
                        self.scan_results.append(port)
                        print(f"Port {port} is open.")
            except Exception as e:
                print(f"Error scanning port {port}: {e}")

        end_time = datetime.now()
        print(f"Scan completed in {end_time - start_time}.")

    def directory_busting(self, wordlist_path):
        print(f"Starting directory busting on {self.target}...")
        try:
            with open(wordlist_path, "r") as file:
                directories = file.read().splitlines()

            for directory in directories:
                url = f"http://{self.target}/{directory}"
                response = requests.get(url)
                if response.status_code == 200:
                    print(f"Found directory: {url}")
        except Exception as e:
            print(f"Error during directory busting: {e}")

    def subdomain_enumeration(self, wordlist_path):
        print(f"Starting subdomain enumeration on {self.target}...")
        try:
            with open(wordlist_path, "r") as file:
                subdomains = file.read().splitlines()

            for subdomain in subdomains:
                full_domain = f"{subdomain}.{self.target}"
                try:
                    answers = dns.resolver.resolve(full_domain, "A")
                    for answer in answers:
                        print(f"Found subdomain: {full_domain} -> {answer}")
                except dns.resolver.NXDOMAIN:
                    continue
        except Exception as e:
            print(f"Error during subdomain enumeration: {e}")

    def version_detection(self):
        print(f"Starting version detection on {self.target}...")
        for port in self.scan_results:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((self.target, port))
                    s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    response = s.recv(1024).decode("utf-8", errors="ignore")
                    if "Server:" in response:
                        server_header = response.split("Server:")[1].split("\r\n")[0].strip()
                        print(f"Port {port} service version: {server_header}")
            except Exception as e:
                print(f"Error detecting version on port {port}: {e}")

if __name__ == "__main__":
    scanner = NmapCLI("", (0, 0))
    scanner.show_options()
    
    choice = input("Enter the number of the option you want to perform: ")
    
    if choice in ["1", "2", "3", "4"]:
        target = input("Enter the target IP or domain to scan: ").strip()
        if not target:
            print("Target cannot be empty. Please provide a valid IP or domain.")
            exit(1)

        if choice == "1":
            port_range = input("Enter port range (e.g., 1-1024): ").strip()
            port_range = tuple(map(int, port_range.split('-')))
            scanner = NmapCLI(target, port_range)
            scanner.scan_ports()
        elif choice == "2":
            wordlist = input("Enter path to directory wordlist: ").strip()
            scanner = NmapCLI(target, (0, 0))
            scanner.directory_busting(wordlist)
        elif choice == "3":
            wordlist = input("Enter path to subdomain wordlist: ").strip()
            scanner = NmapCLI(target, (0, 0))
            scanner.subdomain_enumeration(wordlist)
        elif choice == "4":
            port_range = input("Enter port range for version detection (e.g., 1-1024): ").strip()
            port_range = tuple(map(int, port_range.split('-')))
            scanner = NmapCLI(target, port_range)
            scanner.scan_ports()
            scanner.version_detection()
    else:
        print("Invalid choice. Please select a valid option.")
