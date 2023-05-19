import socket
import sys
import struct
 
# Constructs and returns a DNS message, asking for the given
# domain string (e.g. `google.com`).
def build_dns_msg(domain):
    # Header
 
    # Identification
    id = b"\x11\x11"
    # 16 bits of header flags
    flags = b"\x01\x00"
    # Number of questions
    n_quests = b"\x00\x01"  # Single record in first section
    # Number of answers
    n_ans = b"\x00\x00"
    # Number of authority resource records
    n_auth_rr = b"\x00\x00"
    # Number of additional RRs
    n_add_rr = b"\x00\x00"
 
    header = id + flags + n_quests + n_ans + n_auth_rr + n_add_rr
 
    # Body
 
    # Put all domain parts into the body of the message
    # Precede every part with the number of characters in that part
    domain_name = bytes()
    for domain_part in domain.split('.'):
        # e.g. for `com` the format string is:
        # `!b3s`
        domain_name = domain_name + struct.pack("!b" + str(len(domain_part)) + "s",
                                                len(domain_part), bytes(domain_part, "ascii"))
 
    # End domain name with a null-byte
    domain_name = domain_name + b'\x00'
 
    # Type: A
    ty = b'\x00\x01'
    # Class code: 0x0001
    cl = b'\x00\x01'
 
    body = domain_name + ty + cl
 
    return header + body
 
 
# Connects to the given DNS server over UDP, sends the given query,
def run_lookup(dns_server_ip, dns_server_port, query):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (dns_server_ip, dns_server_port))
        data, addr = sock.recvfrom(1024)
        sock.close()
    except Exception as e:
        print("Received no response from the DNS server", dns_server_ip, e)
        sock.close()
        sys.exit()
 
    server_msg = data.split(b',', 0)
 
    # Convert to hex for easier parsing
    msg_hex = server_msg[0].hex()
 
    # Check RCODE
    rcode = int(msg_hex[7])
    if rcode != 0:
        print("Error!")
        if (rcode == 1):
            print("### Format error the name server could not interpret the query.")
        elif (rcode == 2):
            print("### Server failure: the name server was unable to process this query due to a problem with the name server.")
        elif (rcode == 3):
            print("### Non-existed domain")
        elif (rcode == 4):
            print(
                "### Not Implemented: the name server does not support the requested kind of query.")
        elif (rcode == 5):
            print("### Server Refused.")
        else:
            print("### Other errors")
        print("Aborting due to previous error")
        return
    
    parse_responce(msg_hex)
 
 
# Parses responce of DNS server
def parse_responce(msg_hex):
    answer_cnt = int(msg_hex[12:16])
    print("Answer count: ", answer_cnt)
 
    # Retrieve the answers
    answer = msg_hex[2*len(query):]
    for i in range(0, answer_cnt):
        print("Answer ", i+1, ":", sep='')
 
        n = answer[:4]
        answer = answer[4:]
 
        t = answer[:4]
        if (t == "0001"):
            print("TYPE: A")
        elif (t == "0005"):
            print("TYPE: CNAME")
        else:
            print("TYPE: ", t)
        answer = answer[4:]
 
        c = answer[:4]
        if (c == "0001"):
            print("CLASS: IN")
        else:
            print("CLASS: ", c)
        answer = answer[4:]
 
        ttl = answer[:8]
        print("TTL: ", int(ttl, 16), "s")
        answer = answer[8:]
 
        l = answer[:4]
        print("RDLENGTH: ", int(l, 16))
        answer = answer[4:]
 
        rdata = answer[:int(l, 16)*2]
        answer = answer[int(l, 16)*2:]
 
        if (t == "0001"):
            # TYPE is A: read the IP from the RDATA
            a = int(rdata, 16)
            ip4 = a & 0xff
            a = a >> 8
            ip3 = a & 0xff
            a = a >> 8
            ip2 = a & 0xff
            a = a >> 8
            ip1 = a & 0xff
            print("IP: " + str(ip1) + "." + str(ip2) +
                  "." + str(ip3) + "." + str(ip4))
        else:
            # TYPE is CNAME: read CNAME from the RDATA
            cname = ""
            rdata = rdata[2:]
            for i in range(int(l, 16)-3):
                n = rdata[:2]
                n = int(n, 16)
                rdata = rdata[2:]
                if n <= 32:
                    cname = cname + "."
                cname = cname + chr(n)
            print("CNAME: ", cname)
 
        print()
 

if __name__ == '__main__':
    dns_server_ip = sys.argv[1]
    domain_name = sys.argv[2]
    print("Domain: ", domain_name)
    print("Sending query to DNS server", dns_server_ip)
    print()
    query = build_dns_msg(domain_name)
    run_lookup(dns_server_ip, 53, query)