from enum import IntEnum


class OutValue:
    _value = None
    _instance = None

    def set(self, value):
        self._value = value

    def get(self):
        return self._value


class Hostname:
    def _get_name_from_bytes(self, dns_message_bytes: bytes):
        name = []
        for x in self.splitName:
            if isinstance(x, str):
                name.append(x)
            else:
                offset_part = Hostname.from_bytes(
                    dns_message_bytes[x:])._get_name_from_bytes(
                    dns_message_bytes)
                name += offset_part
                break
        return name

    def __init__(self, name: str = None, splitName: list = None):
        if name is not None:
            self.splitName = name.split('.')
            return
        if splitName is not None:
            self.splitName = splitName
            return

    def __str__(self):
        return ' '.join([str(x) for x in self.splitName])

    def get_name(self, dns_message_bytes: bytes = b''):
        return '.'.join(self._get_name_from_bytes(dns_message_bytes))

    def to_bytes(self) -> bytes:
        data_b = b""
        for x in self.splitName:
            if isinstance(x, int):
                data_b += bytes([0b11000000 | (x // 256), x % 256])
                break
            else:
                data_b += len(x).to_bytes(1, byteorder="big")
                data_b += x.encode()
        else:
            data_b += bytes([0])
        return data_b

    @staticmethod
    def from_bytes(data_b: bytes, out_len: OutValue = None,
                   total_data_b: bytes = None):  # -> Hostname
        cur_ind = 0
        splitted_name = []
        while cur_ind < len(data_b):
            if data_b[cur_ind] & 0b11000000:
                offset = int.from_bytes(
                    [data_b[cur_ind] ^ 0b11000000, data_b[cur_ind + 1]],
                    byteorder="big")
                splitted_name.append(offset)

                if out_len:
                    out_len.set(cur_ind + 2)

                return Hostname(splitName=splitted_name)

            if data_b[cur_ind] == 0:
                break

            word_len = data_b[cur_ind]
            splitted_name.append(
                data_b[cur_ind + 1: cur_ind + word_len + 1].decode("utf-8"))
            cur_ind += word_len + 1

        if out_len:
            out_len.set(cur_ind + 1)
        if splitted_name[-1] == 'localnet':
            splitted_name = splitted_name[:-1]
        # print(splitted_name)
        return Hostname(splitName=splitted_name)


class Queries:
    def __init__(self, hostname, q_type):
        self.hostname = hostname
        self.q_type = q_type
        self.q_class = 1

    def to_bytes(self) -> bytes:
        return (self.hostname.to_bytes()
                + self.q_type.to_bytes(2, byteorder="big")
                + self.q_class.to_bytes(2, byteorder="big"))

    @staticmethod
    def from_bytes(data_b: bytes, out_len: OutValue = None,
                   full_data_b: bytes = None):
        out_len_loc = OutValue()
        hostname = Hostname.from_bytes(data_b, out_len_loc, full_data_b)

        qt_index = out_len_loc.get() + 2
        q_type = RType(
            int.from_bytes(data_b[qt_index - 2: qt_index], byteorder="big"))
        if out_len:
            out_len.set(qt_index + 2)

        return Queries(hostname, q_type)


class RType(IntEnum):
    A = 1
    NS = 2
    UNKNOWN = 999


class Flags:
    def __init__(self, QR: bool, AA=False, RCODE=0):
        self.QR = QR
        self.OPCODE = 0
        self.AA = AA
        self.TC = 0
        self.RD = 0
        self.RA = 0
        self.Z = 0
        self.RCODE = RCODE

    def to_bytes(self) -> bytes:
        return ((self.QR << 15) | (self.OPCODE << 11) | (self.AA << 10) | (
                self.TC << 9)
                | (self.RD << 8) | (self.RA << 7) | (
                        self.Z << 4) | self.RCODE).to_bytes(2,
                                                            byteorder="big")

    @staticmethod
    def from_bytes(data_b: bytes):
        QR = bool(data_b[0] & 0b10000000)
        AA = bool(data_b[0] & 0b00000100)
        RCODE = data_b[1] & 0b00001111
        return Flags(QR, AA, RCODE)


class RecordData:
    def __init__(self):
        self.len = 0

    def to_bytes(self) -> bytes:
        pass

    @staticmethod
    def from_bytes(data_b: bytes):
        pass


class Record:
    def __init__(self, hostname: Hostname, r_type: RType,
                 record_data=RecordData()):
        self.hostname = hostname
        self.r_type = r_type
        self.rd_class = 1

        self.ttl = 0  # remember, no cache    # TODO
        self.data = record_data

    def __str__(self):
        splitted_r_data_s = str(self.data).split('\n')
        r_data_s = splitted_r_data_s[0]
        if len(splitted_r_data_s) > 1:
            r_data_s += '\n'.join(['\t' + x for x in splitted_r_data_s[1:]])
        return f"""hostname:\t({self.hostname})
r_type: \t{self.r_type.name}
r_data: \t"{r_data_s}"
"""

    def to_bytes(self) -> bytes:
        return (self.hostname.to_bytes() +
                self.r_type.to_bytes(2, byteorder="big") +
                self.rd_class.to_bytes(2, byteorder="big") +
                self.ttl.to_bytes(4, byteorder="big") +
                self.data.to_bytes())

    @staticmethod
    def from_bytes(data_b: bytes, out_len: OutValue = None,
                   full_data: bytes = None):
        out_len_loc = OutValue()
        hostname = Hostname.from_bytes(data_b, out_len_loc, full_data)
        parse_ind = out_len_loc.get()
        try:
            r_type = RType(int.from_bytes(data_b[parse_ind:parse_ind + 2],
                                          byteorder="big"))
        except ValueError:
            r_type = RType.UNKNOWN

        parse_ind += 8
        data_len = int.from_bytes(data_b[parse_ind:parse_ind + 2],
                                  byteorder="big")
        parse_ind += 2
        r_data = None
        if r_type == r_type.A:
            r_data = RDTypeA.from_bytes(
                data_b[parse_ind - 2: parse_ind + data_len])

        if r_type == r_type.NS:
            r_data = RDTypeNS.from_bytes(
                data_b[parse_ind: parse_ind + data_len])

        if out_len:
            out_len.set(parse_ind + data_len)

        return Record(hostname, r_type, r_data)


class RDTypeA(RecordData):
    def __str__(self):
        return f"{'.'.join([str(x) for x in self.address])}"

    def __init__(self, address: list[int]):
        super().__init__()
        self.len = 4
        self.address = address

    def to_bytes(self) -> bytes:
        data_b = self.len.to_bytes(2, byteorder="big")
        for x in self.address:
            data_b += x.to_bytes(1, byteorder="big")
        return data_b

    @staticmethod
    def from_bytes(data_b: bytes):
        addr = [int(x) for x in data_b[2:]]
        if len(addr) != 4:
            raise Exception("Wrong address")
        return RDTypeA(addr)


class RDTypeNS(RecordData):
    def __str__(self):
        return f"{self.hostname}"

    def __init__(self, hostname: Hostname):
        super().__init__()
        self.hostname = hostname
        self.len = len(self.hostname.to_bytes())

    def form_dns_entry(self, message_bytes: bytes):
        return self.hostname.get_name(message_bytes)

    def to_bytes(self) -> bytes:
        data_b = self.hostname.to_bytes()
        return len(data_b).to_bytes(2, byteorder="big") + data_b

    @staticmethod
    def from_bytes(data_b: bytes):
        return RDTypeNS(Hostname.from_bytes(data_b))


class DNSMessage:
    def __init__(self, ID: int, flags: Flags, queries: list[Queries] = [],
                 answers: list[Record] = [], auth_rrs: list[Record] = [],
                 add_rrs: list[Record] = []):
        self.id = ID
        self.flags = flags
        self.flags.RD = 1
        self.queries = queries
        self.answers = answers
        self.auth_rrs = auth_rrs
        self.add_rrs = add_rrs

    def __str__(self):
        return f"""ID: {str(self.id.to_bytes(2, byteorder="big"))}
flags: {self.flags.__dict__}
queries_count: {self.queries_count}
answers_count: {self.answers_count}
auth_rr_count: {self.auth_rrs_count}
add_rr_count: {self.add_rrs_count}"""

    @property
    def queries_count(self):
        return len(self.queries)

    @property
    def answers_count(self):
        return len(self.answers)

    @property
    def auth_rrs_count(self):
        return len(self.auth_rrs)

    @property
    def add_rrs_count(self):
        return len(self.add_rrs)

    def to_bytes(self) -> bytes:
        return (self.id.to_bytes(2, byteorder="big") +
                self.flags.to_bytes() +
                self.queries_count.to_bytes(2, byteorder="big") +
                self.answers_count.to_bytes(2, byteorder="big") +
                self.auth_rrs_count.to_bytes(2, byteorder="big") +
                self.add_rrs_count.to_bytes(2, byteorder="big") +
                b"".join([x.to_bytes() for x in self.queries]) +
                b"".join([x.to_bytes() for x in self.answers]) +
                b"".join([x.to_bytes() for x in self.auth_rrs]) +
                b"".join([x.to_bytes() for x in self.add_rrs]))

    @staticmethod
    def from_bytes(data_b: bytes):
        ID = int.from_bytes(data_b[:2], byteorder="big")
        flags = Flags.from_bytes(data_b[2:4])
        queries_count = int.from_bytes(data_b[4:6], byteorder="big")
        answers_count = int.from_bytes(data_b[6:8], byteorder="big")
        auth_rr_count = int.from_bytes(data_b[8:10], byteorder="big")
        add_rr_count = int.from_bytes(data_b[10:12], byteorder="big")

        # print(ID,flags,queries_count,answers_count,auth_rr_count,add_rr_count)
        parse_ind = 12
        queries = []
        saved_full_data = data_b[parse_ind:]
        for i in range(queries_count):
            out_len = OutValue()
            queries.append(Queries.from_bytes(data_b[parse_ind:], out_len,
                                              saved_full_data))
            parse_ind += out_len.get()

        answers = []
        for i in range(answers_count):
            out_len = OutValue()
            answers.append(
                Record.from_bytes(data_b[parse_ind:], out_len, saved_full_data))
            parse_ind += out_len.get()

        auth_rrs = []
        for i in range(auth_rr_count):
            out_len = OutValue()
            auth_rrs.append(
                Record.from_bytes(data_b[parse_ind:], out_len, saved_full_data))
            parse_ind += out_len.get()

        add_rrs = []
        for i in range(add_rr_count):
            out_len = OutValue()
            add_rrs.append(
                Record.from_bytes(data_b[parse_ind:], out_len, saved_full_data))
            parse_ind += out_len.get()

        return DNSMessage(ID, flags, queries, answers, auth_rrs, add_rrs)
