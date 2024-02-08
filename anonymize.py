from yacryptopan import CryptoPAn

# Initialize CryptoPAn with a 32-byte secret key
secret_key = b'secretkeysecretkeysecretkeysecre'
crypto_pan = CryptoPAn(secret_key)

# Anonymize an IPv4 address
ip_address_v4 = '192.168.1.1'
anonymized_ip_v4 = crypto_pan.anonymize(ip_address_v4)
print("Original IPv4:", ip_address_v4)
print("Anonymized IPv4:", anonymized_ip_v4)

# Anonymize an IPv6 address
ip_address_v6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
anonymized_ip_v6 = crypto_pan.anonymize(ip_address_v6)
print("Original IPv6:", ip_address_v6)
print("Anonymized IPv6:", anonymized_ip_v6)
