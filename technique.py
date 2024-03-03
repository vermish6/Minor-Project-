import os
from scapy.all import *
from yacryptopan import CryptoPAn
import ipaddress

subnets = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('103.27.10.0/24'),
    ipaddress.ip_network('103.27.11.0/24'),
    ipaddress.ip_network('103.27.8.0/24'),
    ipaddress.ip_network('103.27.9.0/24'),
]

def is_file_write_complete(file_path, wait_time=2, check_interval=0.5):
    """
    Check if the file at `file_path` has stopped growing.
    `wait_time` specifies how long to wait to confirm the file isn't growing.
    `check_interval` specifies how often to check the file size.
    """
    prev_size = -1
    stable_time = 0
    while stable_time < wait_time:
        try:
            current_size = os.path.getsize(file_path)
        except OSError:
            # If the file does not exist or is inaccessible, we can't proceed.
            return False
        if current_size == prev_size:
            stable_time += check_interval
        else:
            stable_time = 0
            prev_size = current_size
        time.sleep(check_interval)
    return True

def is_in_subnets(ip, subnets):
    return any(ipaddress.ip_address(ip) in subnet for subnet in subnets)

def anonymize_ip(ip_address, crypto_pan):
    return crypto_pan.anonymize(ip_address)

def anonymize_pcap(input_pcap_file, output_folder, secret_key):
    # Initialize CryptoPAn with a 32-byte secret key
    crypto_pan = CryptoPAn(secret_key)

    # Read packets from input pcap file
    packets = rdpcap(input_pcap_file)

    for packet in packets:
        if IP in packet or IPv6 in packet or ARP in packet or ICMP in packet:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if is_in_subnets(src_ip, subnets):
                    packet[IP].src = anonymize_ip(src_ip, crypto_pan)
                
                if is_in_subnets(dst_ip, subnets):
                    packet[IP].dst = anonymize_ip(dst_ip, crypto_pan)
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                if is_in_subnets(src_ip, subnets):
                    packet[IPv6].src = anonymize_ip(src_ip, crypto_pan)
                
                if is_in_subnets(dst_ip, subnets):
                    packet[IPv6].dst = anonymize_ip(dst_ip, crypto_pan)
            elif ARP in packet:
                src_ip = packet[ARP].src
                dst_ip = packet[ARP].dst
                if is_in_subnets(src_ip, subnets):
                    packet[ARP].src = anonymize_ip(src_ip, crypto_pan)
                
                if is_in_subnets(dst_ip, subnets):
                    packet[ARP].dst = anonymize_ip(dst_ip, crypto_pan)
            elif ICMP in packet:
                src_ip = packet[ICMP].src
                dst_ip = packet[ICMP].dst
                if is_in_subnets(src_ip, subnets):
                    packet[ICMP].src = anonymize_ip(src_ip, crypto_pan)
                
                if is_in_subnets(dst_ip, subnets):
                    packet[ICMP].dst = anonymize_ip(dst_ip, crypto_pan)

    # Construct output file path with input file name appended with '-anonymized'
    filename = os.path.basename(input_pcap_file)
    output_pcap_file = os.path.join(output_folder, os.path.splitext(filename)[0] + "-anonymized.pcap")

    # Write anonymized packets to output pcap file
    wrpcap(output_pcap_file, packets)
    return output_pcap_file

def process_files(source_folder, destination_folder, secret_key,duration):
    # Check if source folder exists
    if not os.path.exists(source_folder):
        print(f"Source folder '{source_folder}' does not exist.")
        return

    # Check if destination folder exists, create if not
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
        print(f"Destination folder '{destination_folder}' created.")

    # Get list of files in source folder
    start_time = time.time()
    while time.time() - start_time < duration:
        # Get list of files in source folder
        files = os.listdir(source_folder)

        if not files:
            print(f"No files found in '{source_folder}'.")
            time.sleep(1)  # Wait for 1 second before checking again
            continue

        # Process each file in the source folder
        for file in files:
            source_path = os.path.join(source_folder, file)

            if not is_file_write_complete(source_path):
                print(f"The file '{file}' is still being written. Skipping for now.")
                continue

            try:
                output_pcap_file = anonymize_pcap(source_path, destination_folder, secret_key)
                print(f"Anonymized '{file}' and saved to '{output_pcap_file}'")
                os.remove(source_path)
            except Exception as e:
                print(f"Error processing file '{file}': {e}")

        time.sleep(1)  # Wait for 1 second before checking again

if __name__ == "__main__":
    source_folder = "temp_capture"
    destination_folder = "renamedfile"
    secret_key = b'secretkeysecretkeysecretkeysecre'
    duration=3600*24

    process_files(source_folder, destination_folder, secret_key,duration)
