#!/bin/bash

#1.1 Get from the user a network to scan.
#1.4 Make sure the input is valid.
function USER_INPUT () {
    while true; do
        read -p "Please enter the network range you would like to scan in CIDR notation (your IP is $(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1)): " NET

# Validate the input
        if [[ ! "$NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] && [[ ! "$NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "Error: Invalid input format. Please enter a valid IP address (e.g., 192.168.1.0/24) or a single IP address."
        else
            break  # Exit the loop if a valid input is provided
        fi
    done

# Check if it's a single IP or a network range
    if [[ "$NET" =~ / ]]; then
        echo "Scanning network range: $NET"

    else
        echo "Scanning single IP: $NET"

    fi
}



# Function to prompt user for directory name input and validate it
#1.2 Get from the user a name for the output directory.
#1.4 Make sure the input is valid.


function GET_DIR_NAME() {
    while true; do
        read -p "Please enter directory name for the results:" NAME

#Validate the directory name input
        if [[ ! "$NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            echo "Error: Invalid directory name. Please use only letters, numbers, hyphens, and underscores."
        else
            break
        fi
    done
}

GET_DIR_NAME

#Check if the directory already exists
if [ -d "$HOME/Desktop/$NAME" ]; then
    echo "Error: Directory '$NAME' already exists on your desktop. plz try again."
    GET_DIR_NAME
fi

#Create the main directory on the user's Desktop
mkdir -p "$HOME/Desktop/$NAME" > /dev/null 2>&1

#Check if directory creation was successful
if [ $? -eq 0 ]; then
    echo "[+] Created main directory '$NAME' on your Desktop."
else
    echo "Error: Failed to create main directory '$NAME' on your Desktop."
fi




USER_INPUT

function BASIC_SCAN () {

nmap -p- -sV -oN "/home/kali/Desktop/$NAME/tcp_scan" "$NET"

#look for udp ports
masscan -pU:1-65535 "$NET" --rate=1000 -oG "/home/kali/Desktop/$NAME/udp_scan"


}

function NMAP_BRUT () {	
	
mkdir -p "/home/kali/Desktop/$NAME/brut" > /dev/null 2>&1
	
read -p "Do you want to use your own password list? (yes/no): " use_own_passwords

if [[ "$use_own_passwords" == "yes" ]]; then
    read -p "Enter the path to your passwords file: " passwords_file
    nmap --script ssh-brute --script-args "passdb=$passwords_file" $NET -sV > "/home/kali/Desktop/$NAME/brut/ssh_nmap_brut"
    nmap --script ftp-brute --script-args "passdb=$passwords_file" $NET -sV > "/home/kali/Desktop/$NAME/brut/ftp_nmap_brut"
    nmap --script telnet-brute --script-args "passdb=$passwords_file" $NET -sV > "/home/kali/Desktop/$NAME/brut/telnet_nmap_brut"



else
    nmap $NET --script=ssh-brute.nse -sV > "/home/kali/Desktop/$NAME/brut/ssh_nmap_brut"
    nmap $NET --script=ftp-brute.nse -sV > "/home/kali/Desktop/$NAME/brut/ftp_nmap_brut"
    nmap $NET --script=telnet-brute.nse -sV > "/home/kali/Desktop/$NAME/brut/telnet_nmap_brut"
fi


echo "found password:"
for file in /home/kali/Desktop/$NAME/brut/*; do
    cat "$file" | grep -A1 "|   Accounts:" | awk 'NR==2 {print $2}'
done | tee /home/kali/Desktop/$NAME/brut/found_pass.txt

}

#3.1 Mapping vulnerabilities should only take place if Full was chosen.
#3.2 Display potential vulnerabilities via NSE and Searchsploit.
function FULL_SCAN () {

nmap "$NET" --script=vulners.nse -sV -oN  "/home/kali/Desktop/$NAME/nse_scan"

sleep 2

for file in $(ls /home/kali/Desktop/$NAME/nse_scan); do cat "$CVE_NUM" | grep -oP 'CVE-\d{4}-\d{4}'; searchsploit --cve $CVE_NUM >> /home/kali/Desktop/$NAME/cve_sploit ; done

echo "the cve searchsploit potential vulnerabilities results has benn saved in /home/kali/Desktop/$NAME/nse_scan/cve_sploit"
	
	
NMAP_BRUT

full_scan_chosen=1	
}


# 1.3 Allow the user to choose 'Basic' or 'Full'.
echo -e "Please enter the number of the scan you would like to use:\n1 - basic\n2 - full"
read SCAN

# Check the user's choice and execute the corresponding scan
#1.3.1 Basic: scans the network for TCP and UDP, including the service version and weak passwords.
#1.3.2 Full: include Nmap Scripting Engine (NSE), weak passwords, and vulnerability analysis.
#1.4 Make sure the input is valid.
case $SCAN in
    1)
        # Execute basic scan function
        echo "Running basic scan..."
        BASIC_SCAN
        ;;
    2)
        # Execute full scan function
        echo "Running full scan..."
        BASIC_SCAN
        FULL_SCAN
        ;;
    *)
        echo "Invalid option. Please enter 1 for basic scan or 2 for full scan."
        exit 1
        ;;
esac


#4.2 At the end, show the user the found information.
function SHOW_RESULTS () {
    echo -e "\nResults Summary:"

    echo -e "\nTCP Scan Results:"
    cat "$HOME/Desktop/$NAME/tcp_scan"

    echo -e "\nUDP Scan Results:"
    cat "$HOME/Desktop/$NAME/udp_scan"

    echo -e "\nFound Passwords:"
    cat "$HOME/Desktop/$NAME/brut/found_pass.txt"

}

#4.3 Allow the user to search inside the results.
function SEARCH_RESULTS () {
    read -p "Enter the keyword to search in the results: " keyword
    echo -e "\nSearch Results for '$keyword':"

    echo -e "\nResults matching '$keyword' in all files under $HOME/Desktop/$NAME:"
    
    cd "$HOME/Desktop/$NAME"
    grep -ri "$keyword"
    PROMPT_SEARCH
}

SHOW_RESULTS

function PROMPT_SEARCH () {
    while true; do
        read -p "Do you want to search inside the results? (yes/no): " search_choice
        if [[ "$search_choice" == "yes" ]]; then
            SEARCH_RESULTS
        elif [[ "$search_choice" == "no" ]]; then
            break  
        else
            echo "Invalid choice. Please enter 'yes' or 'no'."
        fi
    done
}

#4.4 Allow to save all results into a Zip file.
function SAVE_RESULTS () {
	cd /home/kali/Desktop
    zip -r "./results.zip" "./$NAME" >/dev/null 2>&1
   
    if [ $? -eq 0 ]; then
        echo "[+] All results have been saved to $HOME/Desktop/$NAME/results.zip"
    else
        echo "Error: Failed to save results to a zip file."
    fi
}


# call the first search
PROMPT_SEARCH

#4.4 Allow to save all results into a Zip file.
read -p "Do you want to save all results into a zip file? (yes/no): " save_choice
if [[ "$save_choice" == "yes" ]]; then
    SAVE_RESULTS
else
    echo "Exiting without saving results to a zip file."
    exit 0
fi
