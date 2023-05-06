from dns_entities import *
import socket
import random
import dns_resolver
from dns_resolver import ResolverResponse

PORT = 53
IP = "127.0.0.1"


def resolve(dns_mes: DNSMessage) -> ResolverResponse:
    q = dns_mes.queries[0]
    hostname, q_type = q.hostname.get_name(), q.q_type
    return dns_resolver.get_addresses(hostname, q_type, dns_mes, True)


def parse_dns_message(client_request: bytes) -> DNSMessage:
    try:
        return DNSMessage.from_bytes(client_request)
    except Exception:
        return None


def create_response(user_dns_message: DNSMessage, result: ResolverResponse):
    ip_addresses = result.ips
    additional = result.add

    ID = user_dns_message.id
    hostname = user_dns_message.queries[0].hostname.get_name()
    q_type = user_dns_message.queries[0].q_type
    queries = [Queries(Hostname(hostname), q_type)]
    flags = Flags(QR=True)
    answers = []
    addit_rrs = []
    if q_type == RType.A:
        for ip in ip_addresses:
            ans_rd = RDTypeA([int(x) for x in ip.split('.')])
            ans_r = Record(Hostname.from_bytes(b"\xc0\x0c"), RType.A, ans_rd)
            answers.append(ans_r)
    if q_type == RType.NS:
        dns_names = []
        for ip in ip_addresses:
            ans_rd = RDTypeNS(Hostname(ip))
            dns_names.append(ip)
            ans_r = Record(Hostname.from_bytes(b"\xc0\x0c"), RType.NS, ans_rd)
            answers.append(ans_r)

        if additional:
            for add in additional:
                add_rd = RDTypeA([int(x) for x in add.split('.')])
                add_r = Record(Hostname(dns_names.pop(0)), RType.A, add_rd)
                addit_rrs.append(add_r)

    result = DNSMessage(ID, flags, queries, answers, add_rrs=addit_rrs) if len(
        addit_rrs) > 0 else DNSMessage(ID, flags, queries, answers,
                                       add_rrs=addit_rrs)
    return result


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
        result = resolve(dns_mes)
        print('----------------------------------------')
        if result:
            response = create_response(dns_mes, result)
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
