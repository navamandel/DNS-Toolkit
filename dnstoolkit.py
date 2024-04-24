import ssl
import sys
import socket
import certifi
import validators

from scapy.layers.inet import IP, UDP
from scapy.all import sniff, select, RandShort, sr1
from scapy.layers.dns import DNS
from scapy.layers.dns import DNSQR, DNSRR

chosen_dns_server = "8.8.8.8"  # Google's Public DNS server

def caa(domainca):

    # Fetching CA certificates from the Python's ssl module
    ca_cert_path = certifi.where()
    context = ssl.create_default_context(cafile=ca_cert_path)

    with socket.create_connection((domainca, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domainca) as ssock:
            # Get the SSL certificate from the server
            cert = ssock.getpeercert()


    issuer = dict(x[0] for x in cert['issuer'])

    print('CAA Record:')
    print('Issuer: ', issuer.get('organizationName', ''))

def dnsmap(domaindm):
    input_file_path = "wordlist_TLAs.txt"
    output_file_path = "server_mapping.txt"
    max_attempts = 3

    # Function to perform DNS lookup for a domain
    def resolve_domain(domaindmt):

        for attempt in range(max_attempts):
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(2)

            try:
                dns_port = 53
                dns_query = bytearray()
                dns_query += b'\x00\x00'  # Query ID
                dns_query += b'\x01\x00'  # Flags
                dns_query += b'\x00\x01'  # Questions
                dns_query += b'\x00\x00'  # Answer RRs
                dns_query += b'\x00\x00'  # Authority RRs
                dns_query += b'\x00\x00'  # Additional RRs
                dns_query += bytes(''.join(chr(len(label)) + label for label in domaindmt.split('.')), 'utf-8')
                dns_query += b'\x00'      # End of domain name
                dns_query += b'\x00\x01'  # Query Type
                dns_query += b'\x00\x01'  # Query Class

                udp_socket.sendto(dns_query, (chosen_dns_server,dns_port))
                # Receive DNS repsonse
                response, _ = udp_socket.recvfrom(1024)

                # Parse DNS response
                if len(response) > 0:
                    ip_addresses = []
                    num_answers = response[6] * 256 + response[7]
                    offset = 12  # Start from answer section
                    for _ in range(num_answers):
                        if response[offset] == 0xC0:
                            offset += 2
                        else:
                            offset += 1
                            while response[offset] != 0:
                                offset += 1
                            offset += 5
                            ip_address = ".".join(str(byte) for byte in response[offset - 4:offset])
                            ip_addresses.append(ip_address)
                            offset += 6
                    return ip_addresses[1:]

            except socket.timeout:
                pass

            finally:
                udp_socket.close()
        return None

    with open(input_file_path, 'r') as input_file:
        for domaint in input_file:
            domaint = domaint.strip()
            ip_addresses = resolve_domain(str(domaint) + '.' + str(domaindm))
            if ip_addresses:
                print(f"Domain '{domaint + '.' + domaindm}' mapped to servers: {' '.join(ip_addresses)}\n")



def whois(domainwi):
    # Define whois server and port
    whois_server = 'whois.iana.org'
    port = 53

    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect((whois_server, port))
    my_socket.sendall(f"{domainwi}\r\n".encode())

    response = ''
    while True:
        # Set a timeout for receiving the response
        my_socket.settimeout(5)  # 5 second timeout
        try:
            packet = my_socket.recv(1024)
            if not packet:
                break
            response += packet.decode()

        except socket.timeout:
            print("Timeout occured while receiving response")
            break

    print(response)
    my_socket.close()



if __name__ == "__main__":

    domain = sys.argv[2]
    chosen_query = sys.argv[1]

    if validators.domain(domain):
        if chosen_query == 'dig':
            caa(domain)
        elif chosen_query == 'dnsmap':
            dnsmap(domain)
        elif chosen_query == 'whois':
            whois(domain)
        else:
            "Error: Please enter valid command"
    else:
        print("Error! Domain not found")



