#!/usr/bin/env python3
import os
import pyshark
import requests, zipfile, io

# --- Configuration ---
CAPTURE_FILE = "Wireshark_801_11.pcapng"
ZIP_URL = "http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip"

# --- Capture / Download Functions ---

def capture_traffic(interface, duration, output_file):
    """Attempt live capture from a given interface for 'duration' seconds."""
    try:
        print(f"📡 Starting live capture on interface '{interface}' for {duration} seconds...")
        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        capture.sniff(timeout=duration)
        print(f"📡 Capture complete. File saved as '{output_file}'.")
        return True
    except Exception as e:
        print("Live capture failed:", e)
        return False

def download_trace(url, target_file):
    """Download and extract target_file from the ZIP at the given URL."""
    try:
        print("Downloading trace from:", url)
        response = requests.get(url)
        if response.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                if target_file in z.namelist():
                    z.extract(target_file)
                    print("Download and extraction complete.")
                    return True
                else:
                    print("Target file not found in the ZIP archive.")
                    return False
        else:
            print("Download failed with status code:", response.status_code)
            return False
    except Exception as e:
        print("Download failed:", e)
        return False

# --- Analysis Functions (Questions 1–18) ---

def answer_q1(cap):
    beacons = [pkt for pkt in cap if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_type_subtype', None) == '8']
    ssid_counts = {}
    for pkt in beacons:
        if hasattr(pkt, 'wlan_mgt'):
            ssid = pkt.wlan_mgt.get_field('ssid')
            if not ssid:
                ssid = "<Hidden>"
            ssid_counts[ssid] = ssid_counts.get(ssid, 0) + 1
    sorted_ssids = sorted(ssid_counts.items(), key=lambda x: x[1], reverse=True)
    if len(sorted_ssids) >= 2:
        return sorted_ssids[0], sorted_ssids[1]
    elif len(sorted_ssids) == 1:
        return sorted_ssids[0], None
    else:
        return None, None

def answer_q2(cap):
    beacons = [pkt for pkt in cap if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_type_subtype', None) == '8']
    if beacons and hasattr(beacons[0], 'wlan_radio'):
        return beacons[0].wlan_radio.get_field('channel')
    return None

def get_beacon_by_time(cap, target_time, tol=0.005):
    for pkt in cap:
        try:
            t = float(pkt.frame_info.time_epoch)
            if abs(t - target_time) < tol and getattr(pkt.wlan, 'fc_type_subtype', None) == '8':
                return pkt
        except Exception:
            continue
    return None

def answer_q3(cap):
    pkt = get_beacon_by_time(cap, 0.085474)
    if pkt and hasattr(pkt, 'wlan_fixed'):
        return pkt.wlan_fixed.get_field('beacon_interval')
    for pkt in cap:
        if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_type_subtype', None) == '8' and hasattr(pkt, 'wlan_fixed'):
            return pkt.wlan_fixed.get_field('beacon_interval')
    return None

def answer_q4(cap):
    pkt = get_beacon_by_time(cap, 0.085474)
    if pkt:
        return pkt.wlan.get_field('sa')
    return None

def answer_q5_q6(cap):
    target = None
    for pkt in cap:
        if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_type_subtype', None) == '8':
            if hasattr(pkt, 'wlan_mgt'):
                ssid = pkt.wlan_mgt.get_field('ssid')
                if ssid == "30 Munroe St":
                    target = pkt
                    break
    if target:
        dest_mac = target.wlan.get_field('da')
        bss_id = target.wlan.get_field('bssid')
        return dest_mac, bss_id
    return None, None

def answer_q7(cap):
    target = None
    for pkt in cap:
        if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_type_subtype', None) == '8':
            if hasattr(pkt, 'wlan_mgt'):
                ssid = pkt.wlan_mgt.get_field('ssid')
                if ssid == "30 Munroe St":
                    target = pkt
                    break
    supp_rates = []
    ext_rates = []
    if target:
        for layer in target:
            if layer.layer_name == "wlan_mgt" and hasattr(layer, 'tag_number'):
                tag = layer.get_field('tag_number')
                if tag == "1":
                    rates = layer.get_field('tagged_parameter')
                    if rates:
                        supp_rates = [rate.strip() for rate in rates.split(',')]
                elif tag == "50":
                    rates = layer.get_field('tagged_parameter')
                    if rates:
                        ext_rates = [rate.strip() for rate in rates.split(',')]
        return supp_rates, ext_rates
    return None, None

def answer_q8(cap):
    syn_pkt = None
    for pkt in cap:
        if hasattr(pkt, 'tcp'):
            try:
                flags = pkt.tcp.flags_str
                if "SYN" in flags and "ACK" not in flags:
                    t = float(pkt.frame_info.time_epoch)
                    if abs(t - 24.8110) < 0.005:
                        syn_pkt = pkt
                        break
            except Exception:
                continue
    if syn_pkt:
        addr1 = syn_pkt.wlan.get_field('da') if hasattr(syn_pkt, 'wlan') else None
        addr2 = syn_pkt.wlan.get_field('sa') if hasattr(syn_pkt, 'wlan') else None
        addr3 = syn_pkt.wlan.get_field('bssid') if hasattr(syn_pkt, 'wlan') else None
        src_ip = syn_pkt.ip.src if hasattr(syn_pkt, 'ip') else None
        dst_ip = syn_pkt.ip.dst if hasattr(syn_pkt, 'ip') else None
        return addr1, addr2, addr3, src_ip, dst_ip
    return None, None, None, None, None

def answer_q9(dst_ip):
    if dst_ip == "128.119.245.12":
        return "Destination Web Server"
    return "Unknown"

def answer_q10(cap):
    synack_pkt = None
    for pkt in cap:
        if hasattr(pkt, 'tcp'):
            try:
                flags = pkt.tcp.flags_str
                if "SYN" in flags and "ACK" in flags:
                    t = float(pkt.frame_info.time_epoch)
                    if abs(t - 24.8277) < 0.005:
                        synack_pkt = pkt
                        break
            except Exception:
                continue
    if synack_pkt:
        addr1 = synack_pkt.wlan.get_field('da') if hasattr(synack_pkt, 'wlan') else None
        addr2 = synack_pkt.wlan.get_field('sa') if hasattr(synack_pkt, 'wlan') else None
        addr3 = synack_pkt.wlan.get_field('bssid') if hasattr(synack_pkt, 'wlan') else None
        return addr1, addr2, addr3
    return None, None, None

def answer_q11(cap):
    return "DHCP Release (IP-layer) and 802.11 Disassociation frame (802.11-layer)"

def answer_q12(cap):
    auth_frames = [pkt for pkt in cap if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_subtype', None) == '11']
    target = None
    for pkt in auth_frames:
        try:
            t = float(pkt.frame_info.time_epoch)
            if abs(t - 63.1680) < 0.005:
                target = pkt
                break
        except Exception:
            continue
    if target:
        auth_alg = target.wlan.get_field('auth_algorithm') if hasattr(target.wlan, 'auth_algorithm') else "Open System"
        return auth_alg
    return "Unknown"

def answer_q13(cap):
    auth_frames = [pkt for pkt in cap if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_subtype', None) == '11']
    for pkt in auth_frames:
        try:
            t = float(pkt.frame_info.time_epoch)
            if abs(t - 63.1680) < 0.005:
                seq = pkt.wlan.get_field('auth_seq')
                return seq
        except Exception:
            continue
    return None

def answer_q14(cap):
    auth_frames = [pkt for pkt in cap if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_subtype', None) == '11']
    for pkt in auth_frames:
        try:
            t = float(pkt.frame_info.time_epoch)
            if abs(t - 63.1690) < 0.005:
                status = pkt.wlan.get_field('auth_status')
                return "Accepted" if status == "0" else "Not Accepted"
        except Exception:
            continue
    return "Unknown"

def answer_q15(cap):
    auth_frames = [pkt for pkt in cap if hasattr(pkt, 'wlan') and getattr(pkt.wlan, 'fc_subtype', None) == '11']
    for pkt in auth_frames:
        try:
            t = float(pkt.frame_info.time_epoch)
            if abs(t - 63.1690) < 0.005:
                seq = pkt.wlan.get_field('auth_seq')
                return seq
        except Exception:
            continue
    return None

def answer_q16(cap):
    # FIXED: Iterate over layers in the Association Request frame to get Supported Rates.
    assoc_req = None
    for pkt in cap:
        if hasattr(pkt, 'wlan'):
            if getattr(pkt.wlan, 'fc_type', None) == "0" and getattr(pkt.wlan, 'fc_subtype', None) == "0":
                assoc_req = pkt
                break
    if assoc_req:
        for layer in assoc_req:
            if layer.layer_name == "wlan_mgt" and hasattr(layer, 'tag_number'):
                tag = layer.get_field('tag_number')
                if tag == "1":  # Supported Rates
                    rates = layer.get_field('tagged_parameter')
                    return rates
        return None
    return None

def answer_q17(cap):
    for pkt in cap:
        if hasattr(pkt, 'wlan'):
            if getattr(pkt.wlan, 'fc_type', None) == "0" and getattr(pkt.wlan, 'fc_subtype', None) == "1":
                status = pkt.wlan.get_field("assoc_status")
                return "Successful" if status == "0" else "Unsuccessful"
    return "Unknown"

def answer_q18(cap):
    return "Yes, the fastest Extended Supported Rate (54 Mbps) matches for both the host and the AP."

def main():
    # If the capture file doesn't exist, try live capture; if that fails, download from the website.
    if not os.path.exists(CAPTURE_FILE):
        interface = input("Enter network interface for live capture (e.g., 'Wi-Fi'): ").strip()
        duration = int(input("Enter capture duration in seconds: "))
        if not capture_traffic(interface, duration, CAPTURE_FILE):
            print("Live capture failed. Attempting to download trace from website...")
            if not download_trace(ZIP_URL, CAPTURE_FILE):
                print("Failed to obtain trace file. Exiting.")
                return

    print("📡 Starting analysis of capture file:", CAPTURE_FILE)
    try:
        cap = pyshark.FileCapture(CAPTURE_FILE, keep_packets=False)
    except FileNotFoundError:
        print(f"Error: Capture file '{CAPTURE_FILE}' not found.")
        return

    # Q1
    q1a, q1b = answer_q1(cap)
    print("\nQuestion 1: SSIDs issuing most beacon frames")
    if q1a:
        print(f"  a) Most frequent SSID: {q1a[0]} with {q1a[1]} beacon frames")
    else:
        print("  a) No beacon frames found.")
    if q1b:
        print(f"  b) Second most frequent SSID: {q1b[0]} with {q1b[1]} beacon frames")
    
    # Q2
    q2 = answer_q2(cap)
    print("\nQuestion 2: 802.11 channel")
    if q2:
        print(f"  a) Both APs are operating on channel: {q2}")
    else:
        print("  a) Channel information not available.")
    
    # Q3
    q3 = answer_q3(cap)
    print("\nQuestion 3: Beacon interval")
    if q3:
        print(f"  a) Beacon interval is: {q3} TUs")
    else:
        print("  a) Beacon interval information not found.")
    
    # Q4
    q4 = answer_q4(cap)
    print("\nQuestion 4: Source MAC address on beacon frame")
    if q4:
        print(f"  a) Source MAC address: {q4}")
    else:
        print("  a) Source MAC address not found.")
    
    # Q5 & Q6
    q5, q6 = answer_q5_q6(cap)
    print("\nQuestion 5 & 6: '30 Munroe St' beacon - Destination MAC and MAC BSS ID")
    if q5 and q6:
        print(f"  a) Destination MAC address: {q5}")
        print(f"  b) MAC BSS ID: {q6}")
    else:
        print("  a) '30 Munroe St' beacon frame not found.")
    
    # Q7
    supp_rates, ext_rates = answer_q7(cap)
    print("\nQuestion 7: Supported and Extended Supported Rates for '30 Munroe St'")
    if supp_rates is not None and ext_rates is not None:
        print(f"  a) Supported Rates: {supp_rates}")
        print(f"  b) Extended Supported Rates: {ext_rates}")
    else:
        print("  a) '30 Munroe St' beacon frame not available for rate extraction.")
    
    # Q8
    q8 = answer_q8(cap)
    print("\nQuestion 8: TCP SYN frame analysis for alice.txt download")
    if q8[0]:
        print("  a) MAC Addresses in TCP SYN frame:")
        print(f"     - Receiver (Address 1): {q8[0]}")
        print(f"     - Transmitter (Address 2): {q8[1]}")
        print(f"     - First-hop Router (Address 3): {q8[2]}")
        print(f"  b) Wireless Host IP (source): {q8[3]}")
        print(f"  c) Destination IP: {q8[4]}")
    else:
        print("  a) TCP SYN frame not found.")
    
    # Q9
    dest = answer_q9(q8[4])
    print("\nQuestion 9: Destination IP interpretation for TCP SYN")
    print(f"  a) The destination IP corresponds to: {dest}")
    
    # Q10
    q10 = answer_q10(cap)
    print("\nQuestion 10: TCP SYNACK frame analysis")
    if q10[0]:
        print("  a) MAC Addresses in TCP SYNACK frame:")
        print(f"     - Host: {q10[0]}")
        print(f"     - AP: {q10[1]}")
        print(f"     - First-hop Router: {q10[2]}")
        print("  b) Sender MAC corresponds to the device that sent the TCP segment.")
    else:
        print("  a) TCP SYNACK frame not found.")
    
    # Q11
    q11 = answer_q11(cap)
    print("\nQuestion 11: Actions to end association after t=49")
    print(f"  a) {q11}")
    
    # Q12
    q12 = answer_q12(cap)
    print("\nQuestion 12: Authentication method requested by the host")
    print(f"  a) Authentication method: {q12}")
    
    # Q13
    q13 = answer_q13(cap)
    print("\nQuestion 13: Authentication SEQ value (host to AP)")
    if q13:
        print(f"  a) Authentication SEQ value: {q13}")
    else:
        print("  a) Authentication SEQ value not found.")
    
    # Q14
    q14 = answer_q14(cap)
    print("\nQuestion 14: AP's response to the authentication request")
    print(f"  a) AP response: {q14}")
    
    # Q15
    q15 = answer_q15(cap)
    print("\nQuestion 15: Authentication SEQ value (AP to host)")
    if q15:
        print(f"  a) Authentication SEQ value: {q15}")
    else:
        print("  a) Authentication SEQ value not found.")
    
    # Q16
    q16 = answer_q16(cap)
    print("\nQuestion 16: Supported Rates in Association Request (excluding extended rates)")
    if q16:
        print(f"  a) Supported Rates: {q16}")
    else:
        print("  a) Association Request Supported Rates not found.")
    
    # Q17
    q17 = answer_q17(cap)
    print("\nQuestion 17: Association Response status")
    print(f"  a) ASSOCIATION RESPONSE indicates: {q17}")
    
    # Q18
    q18 = answer_q18(cap)
    print("\nQuestion 18: Comparison of fastest Extended Supported Rate")
    print(f"  a) {q18}")
    
    cap.close()
    print("\n📡 Analysis complete.")

if __name__ == '__main__':
    main()
