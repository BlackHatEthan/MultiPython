# MultiPython
## Security Tools Script

This repository contains a Python script that provides a variety of security tools, including port scanning, file downloading, brute force attacks, privilege escalation, vulnerability testing, and more. The tools included are commonly used for penetration testing, network analysis, and ethical hacking.

## Features

- **Port Scanner**: Scans the target IP for open ports in the range 1-1024.
- **File Downloader**: Downloads files from a given URL and saves them to a specified path.
- **String Hasher**: Hashes a given string using the SHA-256 algorithm.
- **DoS (Denial-of-Service) Attack**: Executes a basic ping flood to target a specific IP and port.
- **Brute Force SSH Attack**: Attempts to brute force login to an SSH server using a wordlist.
- **Privilege Escalation**: Attempts to escalate privileges to an administrator on Windows, Linux, or macOS.
- **DNS Lookup**: Performs a DNS lookup to resolve a domain to an IP address.
- **IP Geolocation**: Retrieves geolocation information for a given IP address.
- **XSS (Cross-site Scripting) Test**: Tests a URL for potential XSS vulnerabilities.
- **SQL Injection Test**: Tests a URL for potential SQL injection vulnerabilities.
- **HTTP Header Analysis**: Fetches and displays the HTTP headers of a given URL.
- **OS Fingerprinting**: Identifies the operating system of a target IP using Nmap.
- **SMB Enumeration**: Performs SMB enumeration on a target IP to list available shares.
- **Credential Stuffing Attack**: Attempts a credential stuffing attack using a wordlist on a login page.
- **Remote File Inclusion (RFI) Test**: Tests a URL for potential Remote File Inclusion vulnerabilities.

## Requirements

- Python 3.x
- Required Python Libraries:
  - `requests`
  - `nmap`
  - `dns.resolver`
  - `smbprotocol`

You can install the required libraries using `pip`
