# penetration_testing
This project involves creating a script for network device mapping, identifying ports, services, vulnerabilities and check for weak passwords. The results are stored in a directory and presented to the user.

## Skills Learned
- network device mapping and scanning.
- Identifying and analyzing network vulnerabilities.
- Automating penetration testing tasks to enhance efficiency.

## Tools Used
- Nmap: Network scanning tool for discovering hosts and services.
- Masscan: High-speed network scanner for large-scale mapping, and udp ports.
- Searchsploit: Database of exploits for identifying known vulnerabilities.
- Nmap NSEs: Nmap Scripting Engine scripts for advanced network scanning and vulnerability detection.

## Steps
1. Get User Input
- Get the network to scan.
- Get a name for the output directory.
- Choose 'Basic' or 'Full' scan options.
- Validate the input.
- Weak Credentials Check

2. Check for weak passwords in login services (SSH, RDP, FTP, TELNET).
- Use a built-in or user-supplied password list.
- Mapping Vulnerabilities (Full Scan Only)

3. Use NSE and Searchsploit to identify vulnerabilities.

4. Log and Display Results
- Display each stage in the terminal.
- Show the user the results.
- Allow searching within the results.
- Save all results into a Zip file.

## results
<img width="646" alt="image" src="https://github.com/user-attachments/assets/adad465d-b69d-4c64-9e3d-6f1fd9da8374">

*Ref 1: directory containing the scripts results*
