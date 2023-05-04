from dns_entities import *
import socket
import random

PORT = 53
IP = "127.0.0.1"
ROOT_SERVERS = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
                "192.203.230", "192.5.5.241",
                "192.112.36.4", "198.97.190.53", "192.36.148.17",
                "192.58.128.30", "193.0.14.129", "199.7.83.42",
                "202.12.27.33"]
DNS_REQUEST_SOCK: socket.socket = None


def ip_to_str(ip: list[int]):
    return '.'.join([str(x) for x in ip])

def create_dns_request(server_hostname: str,q_type:RType):
    print(server_hostname,q_type)
    ID = random.Random().randint(0, 1 << 16)
    hostname = Hostname(name=server_hostname)
    queries = [Queries(hostname,q_type)]
    flags = Flags(QR=False)
    return DNSMessage(ID,flags,queries)

def _get_addresses_recursive(hostname: str,q_type:RType, dns_servers_ips_to_polling=ROOT_SERVERS, debug_flag=False) -> list[str]:
    for dns_server_ip in dns_servers_ips_to_polling:
        try:
            data, dns_mes = _get_data_from(hostname,q_type, dns_server_ip)
        except Exception as e:
            if debug_flag:
                print(e)
            continue

        print(dns_mes)
        if dns_mes.flags.AA:
            print(dns_mes.answers[0])
            if dns_mes.answers_count == 0 and debug_flag:
                print(f"No AA answer from {dns_server_ip}")
            return [ip_to_str(ans.data.address) for ans in dns_mes.answers if ans.r_type == RType.A]

        if dns_mes.auth_rrs_count == 0:
            if debug_flag:
                print(f"No NS answer from {dns_server_ip}")
            continue

        try:
            next_dns_servers_ips = _get_next_addresses(data, q_type, dns_mes, dns_mes.add_rrs_count == 0)
        except Exception as e:
            if debug_flag:
                print(f"{e} from {dns_server_ip}")
            continue

        if debug_flag:
            print(f"Responsible for the zone dns ips:")
            print(*next_dns_servers_ips, sep='\n')

        return _get_addresses_recursive(hostname,q_type, next_dns_servers_ips, debug_flag)


def _get_next_addresses(data: bytes, q_type:RType, dns_mes: DNSMessage, recurse_flag=False) -> list[str]:
    next_dns_servers_ips = []
    if recurse_flag:
        auth_rrs_TypeNS = [auth_rr for auth_rr in dns_mes.auth_rrs if auth_rr.r_type == RType.NS]
        for auth_rr in auth_rrs_TypeNS:
            addresses = _get_addresses_recursive(auth_rr.data.get_full_name(data),q_type)
            if addresses:
                next_dns_servers_ips.append(addresses[0])

    else:
        add_rrs_TypeA = [add_rr for add_rr in dns_mes.add_rrs if add_rr.r_type == RType.A]
        next_dns_servers_ips = [ip_to_str(add_rr.data.address) for add_rr in add_rrs_TypeA]
    if len(next_dns_servers_ips) == 0:
        raise Exception(f"No answer")
    print(next_dns_servers_ips)
    return next_dns_servers_ips


def _parse_dns_message(data: bytes) -> DNSMessage:
    if len(data) > 512:
        raise Exception(f"Not supported dns message data length")

    try:
        dns_mes = DNSMessage.from_bytes(data)
    except Exception:
        raise Exception(f"Wrong dns message parse")

    return dns_mes


def _get_data_from(hostname: str,q_type:RType, dns_server_ip) -> (bytes, DNSMessage):
    request = create_dns_request(hostname,q_type)

    try:
        DNS_REQUEST_SOCK.sendto(request.to_bytes(), (dns_server_ip, 53))
        data, addr = DNS_REQUEST_SOCK.recvfrom(1024)
    except Exception:
        raise Exception(f"Unsuccessful data send to {dns_server_ip}")

    try:
        dns_mes = _parse_dns_message(data)
    except Exception as e:
        raise Exception(f"{e} from {dns_server_ip}")

    return data, dns_mes


def get_addresses(hostname: str,q_type:RType, debug_flag=False) -> list[str]:
    global DNS_REQUEST_SOCK
    DNS_REQUEST_SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addresses = _get_addresses_recursive(hostname,q_type, debug_flag=debug_flag)
    return addresses if addresses else []

