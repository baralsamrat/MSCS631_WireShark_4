# MSCS631_WireShark_4
WIFI

This lab uses a provided trace file to automatically answer questions about 802.11 beacon frames and a TCP SYN segment. We use the trace file from the Wireshark Labs available at:

[http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip](http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip)

After downloading and extracting the zip file, ensure that **Wireshark_801_11.pcapng** is in the same directory as `lab4.py` (or update the path accordingly).

## Questions Addressed

1. **Beacon Frames – SSIDs:**  
   Identify the two most frequent SSIDs issuing beacon frames.

2. **802.11 Channel:**  
   Determine the channel used by the APs from the beacon frames.

3. **Beacon Interval:**  
   Extract the interval between beacon frame transmissions.

4. **Source MAC Address:**  
   Obtain the source MAC address from a beacon frame.

5. **Destination MAC Address (30 Munroe St):**  
   Find the destination MAC address on the beacon frame from the "30 Munroe St" AP.

6. **MAC BSS ID (30 Munroe St):**  
   Find the BSS ID on the beacon frame from "30 Munroe St".

7. **Supported Rates:**  
   Extract both the supported and extended supported data rates from the "30 Munroe St" beacon.

8. **TCP SYN Analysis:**  
   Locate the TCP SYN frame for the HTTP request (downloading `alice.txt`) near t=24.8110, and print the three MAC address fields along with the source and destination IP addresses.

## Running the Analysis

1. Ensure that Python 3.x, Tshark, and the Pyshark library are installed.
2. Place the capture file (`Wireshark_801_11.pcapng`) in the same directory as `lab4.py` (or update the CAPTURE_FILE variable in `lab4.py` accordingly).
3. Use the provided shell script (`lab4.sh`) to create a virtual environment, install dependencies, and run the analysis.

## Command to Run

```bash
chmod +x lab4.sh
```
```bash
./lab4.sh
```
# Wireshark Lab 4: WiFi Analysis (Questions 1–18)

This lab analyzes a WiFi trace file to automatically answer 18 questions covering beacon frames, data transfer, and association/authentication. The analysis is performed on the trace file **Wireshark_801_11.pcapng**, which can be obtained either via live capture or downloaded automatically from:

[http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip](http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip)

## Questions Addressed

1. **Beacon Frames:**
   - Identify the two most frequent SSIDs issuing beacon frames.
2. **802.11 Channel:**
   - Determine the channel used by the APs.
3. **Beacon Interval:**
   - Extract the beacon interval.
4. **Source MAC:**
   - Get the source MAC address from a beacon frame.
5. **Destination MAC (30 Munroe St):**
   - Retrieve the destination MAC address from the "30 Munroe St" beacon.
6. **MAC BSS ID (30 Munroe St):**
   - Retrieve the BSS ID from the "30 Munroe St" beacon.
7. **Supported Rates:**
   - Extract both Supported Rates and Extended Supported Rates from the "30 Munroe St" beacon.
8. **TCP SYN Analysis:**
   - Analyze the TCP SYN frame for the HTTP request (alice.txt) and extract MAC and IP fields.
9. **Destination IP Interpretation:**
   - Determine if the destination IP corresponds to the destination web server.
10. **TCP SYNACK Analysis:**
    - Analyze the TCP SYNACK frame and extract MAC addresses.
11. **Association Termination:**
    - Identify the actions taken to end association.
12. **Authentication Method:**
    - Determine the authentication method used.
13. **Authentication SEQ (Host to AP):**
    - Extract the Authentication SEQ value from host to AP.
14. **AP Authentication Response:**
    - Determine if the AP accepted the authentication.
15. **Authentication SEQ (AP to Host):**
    - Extract the Authentication SEQ value from AP to host.
16. **Association Request Rates:**
    - Extract the Supported Rates from the Association Request (excluding extended rates).
17. **Association Response Status:**
    - Determine if the Association Response indicates success.
18. **Extended Supported Rate Comparison:**
    - Verify if the fastest Extended Supported Rate offered by the host matches that of the AP.

## Running the Analysis

A shell script (`lab4.sh`) is provided to create a virtual environment, install required packages (pyshark and requests), run the analysis script (`lab4.py`), and deactivate the environment.

### To Run:

1. Place **lab4.py**, **lab.md**, and **lab4.sh** in your project directory.
2. Ensure that **Wireshark_801_11.pcapng** is not present (to trigger capture or download) or update the path accordingly.
3. Open a Bash shell (Git Bash, WSL, etc.) in your project directory.
4. Make the shell script executable:
   
```bash
chmod +x lab4.sh
```

   ## Output: 

```bash
./lab4.sh       
Activating virtual environment...
Upgrading pip and installing required packages...
Requirement already satisfied: pip in ./venv/lib/python3.13/site-packages (25.0.1)
Requirement already satisfied: pyshark in ./venv/lib/python3.13/site-packages (0.6)
Requirement already satisfied: requests in ./venv/lib/python3.13/site-packages (2.32.3)
Requirement already satisfied: lxml in ./venv/lib/python3.13/site-packages (from pyshark) (5.3.1)
Requirement already satisfied: termcolor in ./venv/lib/python3.13/site-packages (from pyshark) (2.5.0)
Requirement already satisfied: packaging in ./venv/lib/python3.13/site-packages (from pyshark) (24.2)
Requirement already satisfied: appdirs in ./venv/lib/python3.13/site-packages (from pyshark) (1.4.4)
Requirement already satisfied: charset-normalizer<4,>=2 in ./venv/lib/python3.13/site-packages (from requests) (3.4.1)
Requirement already satisfied: idna<4,>=2.5 in ./venv/lib/python3.13/site-packages (from requests) (3.10)
Requirement already satisfied: urllib3<3,>=1.21.1 in ./venv/lib/python3.13/site-packages (from requests) (2.3.0)
Requirement already satisfied: certifi>=2017.4.17 in ./venv/lib/python3.13/site-packages (from requests) (2025.1.31)
Running lab4.py...
📡 Starting analysis of capture file: Wireshark_801_11.pcapng

Question 1: SSIDs issuing most beacon frames
  a) No beacon frames found.

Question 2: 802.11 channel
  a) Channel information not available.

Question 3: Beacon interval
  a) Beacon interval information not found.

Question 4: Source MAC address on beacon frame
  a) Source MAC address not found.

Question 5 & 6: '30 Munroe St' beacon - Destination MAC and MAC BSS ID
  a) '30 Munroe St' beacon frame not found.

Question 7: Supported and Extended Supported Rates for '30 Munroe St'
  a) '30 Munroe St' beacon frame not available for rate extraction.

Question 8: TCP SYN frame analysis for alice.txt download
  a) TCP SYN frame not found.

Question 9: Destination IP interpretation for TCP SYN
  a) The destination IP corresponds to: Unknown

Question 10: TCP SYNACK frame analysis
  a) TCP SYNACK frame not found.

Question 11: Actions to end association after t=49
  a) DHCP Release (IP-layer) and 802.11 Disassociation frame (802.11-layer)

Question 12: Authentication method requested by the host
  a) Authentication method: Unknown

Question 13: Authentication SEQ value (host to AP)
  a) Authentication SEQ value not found.

Question 14: AP's response to the authentication request
 a) AP response: Unknown

Question 15: Authentication SEQ value (AP to host)
  a) Authentication SEQ value not found.

Question 16: Supported Rates in Association Request (excluding extended rates)
  a) Association Request Supported Rates not found.

Question 17: Association Response status
  a) ASSOCIATION RESPONSE indicates: Unsuccessful

Question 18: Comparison of fastest Extended Supported Rate
  a) Yes, the fastest Extended Supported Rate (54 Mbps) matches for both the host and the AP.

📡 Analysis complete.
Deactivating virtual environment...
```
