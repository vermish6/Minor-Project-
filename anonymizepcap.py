from scapy.all import *
from yacryptopan import CryptoPAn

def anonymize_ip(ip_address, crypto_pan):
    return crypto_pan.anonymize(ip_address)

def anonymize_pcap(input_pcap_file, output_pcap_file, secret_key):
    # Initialize CryptoPAn with a 32-byte secret key
    crypto_pan = CryptoPAn(secret_key)

    # Read packets from input pcap file
    packets = rdpcap(input_pcap_file)

    for packet in packets:
        if IP in packet or IPv6 in packet or ARP in packet or ICMP in packet:
            # Anonymize source and destination IP addresses
            if IP in packet:
                packet[IP].src = anonymize_ip(packet[IP].src, crypto_pan)
                packet[IP].dst = anonymize_ip(packet[IP].dst, crypto_pan)
            elif IPv6 in packet:
                packet[IPv6].src = anonymize_ip(packet[IPv6].src, crypto_pan)
                packet[IPv6].dst = anonymize_ip(packet[IPv6].dst, crypto_pan)
            elif ARP in packet:
                packet[ARP].psrc = anonymize_ip(packet[ARP].psrc, crypto_pan)
                packet[ARP].pdst = anonymize_ip(packet[ARP].pdst, crypto_pan)
            elif ICMP in packet:
                packet[ICMP].src = anonymize_ip(packet[ICMP].src, crypto_pan)
                packet[ICMP].dst = anonymize_ip(packet[ICMP].dst, crypto_pan)

    # Write anonymized packets to output pcap file
    wrpcap(output_pcap_file, packets)

if __name__ == "__main__":
    input_pcap_file = 'youtube1.pcap'
    output_pcap_file = 'out1.pcap'
    secret_key = b'secretkeysecretkeysecretkeysecre'
    anonymize_pcap(input_pcap_file, output_pcap_file, secret_key)
