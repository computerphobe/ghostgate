# GhostGate

A low-interaction, multi-protocol honeypot designed to capture threat intelligence on network scanning, brute-force attacks, and malware deployment attempts. This tool simulates common network services to log attacker interactions without exposing a real system to risk.

Key Features 🍯
This honeypot is built with several deceptive and data-gathering capabilities to provide rich insights into attack patterns.

1. Multi-Protocol Support
The honeypot listens on multiple ports simultaneously, emulating a variety of services to attract a wider range of attacks.

FTP: Port 21

Telnet: Port 23

SSH-like: Port 2222

HTTP: Port 8080

2. Fake Service Emulation
Each protocol handler is designed to mimic a real service, keeping attackers engaged long enough to gather valuable data.

Interactive Shells: Both the Telnet and SSH-like services provide a fake command-line interface. They recognize common commands like ls, pwd, whoami, exit, and provide convincing "command not found" responses for others.

Realistic Banners: The services send banners that mimic real software and versions (e.g., "OpenSSH_7.6p1 Ubuntu").

FTP Command Handling: The FTP service correctly handles commands like USER, PASS, PASV, STOR, SYST, and FEAT, following the standard protocol flow.

3. Credential Logging
This is the honeypot's core function. It captures and logs all attempted login credentials.

Username & Password Capture: Logs the username and password from failed login attempts on SSH-like, Telnet, and FTP.

HTTP Basic Auth: Captures base64-encoded credentials from the Authorization header in HTTP requests.

4. Command & Interaction Logging
Beyond just logins, the honeypot records the full session of an attacker's interaction.

Command Execution Log: Every command typed in the fake Telnet and SSH shells is logged with a timestamp and the source IP.

Protocol-Specific Logs: All commands sent over FTP (e.g., USER, PASS, PASV, STOR) and full HTTP request headers are captured.

5. File Upload Trap
The honeypot is configured to act as a decoy for malware and payload drops.

FTP Uploads (STOR): It simulates a successful file upload over FTP and saves the transferred file content to disk.

HTTP Uploads (POST): It correctly handles multipart/form-data POST requests, extracts the file payload, and saves it to a dedicated directory for analysis.

How to Build
This project is developed in C++ and compiled with MinGW GCC on Windows.

Ensure you have a modern C++ compiler (like MinGW-w64 via MSYS2) installed.

Navigate to the directory containing honeypot.cpp.

Use the following command to compile the executable:

Bash

g++ honeypot.cpp -o honeypot.exe -lws2_32 -std=c++17 -mconsole
How to Run
Run the compiled executable from a terminal. For ports below 1024 (21, 23), you may need administrator privileges.

Bash

honeypot.exe
The honeypot will begin listening and log all activity to logs/honeypot.log.

How to Test
You can easily test the functionality using standard command-line tools.

SSH-like (Port 2222) / Telnet (Port 23):

Bash

telnet 127.0.0.1 2222
# Enter credentials, then try commands like ls, whoami, cat /etc/passwd
FTP (Port 21):

Bash

ftp 127.0.0.1 21
# Enter 'anonymous' for user, 'test@example.com' for pass.
# Type 'passive', then 'put your_file.txt' to test the trap.
HTTP (Port 8080):

For a simple GET request, open a browser to http://127.0.0.1:8080.

For a POST file upload, use curl:

Bash

echo "This is a test file." > upload.txt
curl -X POST -F "file=@upload.txt" http://127.0.0.1:8080
Future Enhancements 🚀
This project can be expanded with more advanced features, such as:

Automated File Analysis: Generate MD5/SHA256 hashes of uploaded files and optionally integrate with an antivirus engine like ClamAV.

Smart Credential Flagging: Create a list of common default credentials and flag any attempts that match, indicating a brute-force attack.

Cross-Platform Support: Refactor the code to use a cross-platform networking library (like Boost.Asio or Asio) or conditional compilation for a Linux/macOS version.

Remote Logging: Implement a feature to send logs to a remote server for centralized analysis.

Disclaimer
This software is intended for educational and research purposes only. Do not deploy this honeypot on any network without explicit, written permission from the network administrator. Unauthorized access to computer networks is illegal and unethical. Use this tool responsibly.