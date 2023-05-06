from dns_entities import *
import socket
import random
import dns_resolver

PORT = 53
IP = "127.0.0.1"


def resolve(dns_mes: DNSMessage) -> list[str]:
    q = dns_mes.queries[0]
    hostname, q_type = q.hostname.get_name(), q.q_type
    return dns_resolver.get_addresses(hostname, q_type, dns_mes, True)


def parse_dns_message(client_request: bytes) -> DNSMessage:
    try:
        return DNSMessage.from_bytes(client_request)
    except Exception:
        return None


def create_response(user_dns_message: DNSMessage, ip_addresses: list[str]):
    ID = user_dns_message.id
    hostname = user_dns_message.queries[0].hostname.get_name()
    q_type = user_dns_message.queries[0].q_type
    queries = [Queries(Hostname(hostname), q_type)]
    flags = Flags(QR=True)
    answers = []
    if q_type == RType.A:
        for ip in ip_addresses:
            ans_rd = RDTypeA([int(x) for x in ip.split('.')])
            ans_r = Record(Hostname.from_bytes(b"\xc0\x0c"), RType.A, ans_rd)
            answers.append(ans_r)
    if q_type == RType.NS:
        for ip in ip_addresses:
            ans_rd = RDTypeNS(Hostname(ip))
            ans_r = Record(Hostname.from_bytes(b"\xc0\x0c"), RType.NS, ans_rd)
            answers.append(ans_r)

    return DNSMessage(ID, flags, queries, answers)


def create_fail_response(user_dns_message: DNSMessage):
    try:
        ID = user_dns_message.id
        hostname = user_dns_message.queries[0].hostname.get_name()
        queries = [Queries(Hostname(hostname), RType.A)]
    except Exception:
        ID = 0
        hostname = Hostname.from_bytes(b'\x00')
        queries = [Queries(hostname, RType.A)]

    flags = Flags(QR=True, RCODE=1)
    return DNSMessage(ID, flags, queries)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))

    while True:
        data, addr = sock.recvfrom(512)
        dns_mes = parse_dns_message(data)
        if not dns_mes:
            create_fail_response(dns_mes)
        ip_addresses = resolve(dns_mes)
        print('----------------------------------------')
        if ip_addresses:
            response = create_response(dns_mes, ip_addresses)
        else:
            response = create_fail_response(dns_mes)

        try:
            sock.sendto(response.to_bytes(), addr)
            print(f"Successfully response to {addr[0]}:{addr[1]}")
        except Exception as e:
            print(f"Unsuccessfully response to {addr[0]}:{addr[1]}")
            print("Exception:")
            print(e)


if __name__ == "__main__":
    main()
