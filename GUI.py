import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import requests
import dns.resolver
import threading
from datetime import datetime

class WebEnumerationGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Enumeration Tool")
        self.root.configure(bg="#2C3E50")
        
        tk.Label(root, text="Target (IP/Domain):", bg="#2C3E50", fg="white", font=("Arial", 12)).pack(pady=5)
        self.target_entry = tk.Entry(root, width=50, font=("Arial", 12))
        self.target_entry.pack(pady=5)
        
        self.scan_result = tk.Text(root, height=15, width=80, bg="#ECF0F1", font=("Arial", 10))
        self.scan_result.pack(pady=10)
        
        button_frame = tk.Frame(root, bg="#2C3E50")
        button_frame.pack()
        
        button_style = {"font": ("Arial", 12), "bg": "#3498DB", "fg": "white", "padx": 10, "pady": 5, "bd": 3, "relief": "raised"}
        
        tk.Button(button_frame, text="Port Scan", command=lambda: self.run_thread(self.scan_ports), **button_style).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(button_frame, text="Directory Busting", command=lambda: self.run_thread(self.directory_busting), **button_style).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(button_frame, text="Subdomain Enumeration", command=lambda: self.run_thread(self.subdomain_enumeration), **button_style).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(button_frame, text="Version Detection", command=lambda: self.run_thread(self.version_detection), **button_style).grid(row=1, column=1, padx=5, pady=5)
        
    def run_thread(self, func):
        thread = threading.Thread(target=func)
        thread.start()
    
    def scan_ports(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target.")
            return
        
        self.scan_result.insert(tk.END, f"Scanning ports on {target}...\n")
        for port in range(1, 1025):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((target, port)) == 0:
                        self.scan_result.insert(tk.END, f"Port {port} is open.\n")
            except Exception as e:
                self.scan_result.insert(tk.END, f"Error scanning port {port}: {e}\n")
    
    def directory_busting(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target.")
            return
        
        wordlist_path = filedialog.askopenfilename(title="Select Wordlist")
        if not wordlist_path:
            return
        
        self.scan_result.insert(tk.END, f"Starting directory busting on {target}...\n")
        try:
            with open(wordlist_path, "r") as file:
                for directory in file.read().splitlines():
                    url = f"http://{target}/{directory}"
                    response = requests.get(url)
                    if response.status_code == 200:
                        self.scan_result.insert(tk.END, f"Found: {url}\n")
        except Exception as e:
            self.scan_result.insert(tk.END, f"Error: {e}\n")
    
    def subdomain_enumeration(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target.")
            return
        
        wordlist_path = filedialog.askopenfilename(title="Select Wordlist")
        if not wordlist_path:
            return
        
        self.scan_result.insert(tk.END, f"Starting subdomain enumeration on {target}...\n")
        try:
            with open(wordlist_path, "r") as file:
                for subdomain in file.read().splitlines():
                    full_domain = f"{subdomain}.{target}"
                    try:
                        answers = dns.resolver.resolve(full_domain, "A")
                        for answer in answers:
                            self.scan_result.insert(tk.END, f"Found: {full_domain} -> {answer}\n")
                    except dns.resolver.NXDOMAIN:
                        continue
        except Exception as e:
            self.scan_result.insert(tk.END, f"Error: {e}\n")
    
    def version_detection(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target.")
            return
        
        self.scan_result.insert(tk.END, f"Starting version detection on {target}...\n")
        for port in range(1, 1025):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((target, port))
                    s.send(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                    response = s.recv(1024).decode("utf-8", errors="ignore")
                    if "Server:" in response:
                        server_header = response.split("Server:")[1].split("\r\n")[0].strip()
                        self.scan_result.insert(tk.END, f"Port {port}: {server_header}\n")
            except Exception as e:
                self.scan_result.insert(tk.END, f"Error on port {port}: {e}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebEnumerationGUI(root)
    root.mainloop()
