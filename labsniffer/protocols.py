import ipaddress
import struct

from .models import Packet


class Malformed(ValueError):
    pass


def require(data, offset, length, label):
    if offset < 0 or length < 0 or offset + length > len(data):
        raise Malformed(f"{label} 长度不足：偏移 {offset}，需要 {length}，可用 {max(0, len(data) - offset)}")


def u16(data, offset):
    require(data, offset, 2, "uint16")
    return struct.unpack_from("!H", data, offset)[0]


def u32(data, offset):
    require(data, offset, 4, "uint32")
    return struct.unpack_from("!I", data, offset)[0]


def options(data, tcp=False):
    output, offset = [], 0
    while offset < len(data):
        kind = data[offset]
        if kind == 0:
            output.append({"type": 0})
            break
        if kind == 1:
            output.append({"type": 1})
            offset += 1
            continue
        require(data, offset, 2, "TCP/IP 选项")
        length = data[offset + 1]
        if length < 2:
            raise Malformed("TCP/IP 选项长度小于 2")
        require(data, offset, length, "TCP/IP 选项")
        value = data[offset + 2:offset + length]
        item = {"type": kind, "length": length, "data": value.hex()}
        if tcp and kind == 2 and length == 4:
            item["MSS"] = u16(value, 0)
        output.append(item)
        offset += length
    return output


def parse_packet(raw):
    packet = Packet(raw)
    packet.layer("Frame", {"number": raw.number, "timestamp_ns": raw.timestamp_ns, "len": raw.wirelen,
                           "caplen": raw.caplen, "linktype": raw.linktype, "truncated": raw.caplen < raw.wirelen})
    if raw.caplen < raw.wirelen:
        packet.errors.append("捕获截断：捕获长度小于线上长度")
    try:
        data, kind = link_layer(packet)
        if kind == 0x0806:
            parse_arp(packet, data)
        elif kind == 0x0800:
            parse_ipv4(packet, data)
        elif kind == 0x86DD:
            parse_ipv6(packet, data)
        elif kind is not None:
            packet.summary = f"未知 EtherType 0x{kind:04x}"
    except Malformed as error:
        packet.errors.append(str(error))
    if not packet.summary:
        packet.summary = f"{packet.src} → {packet.dst}" if packet.src else packet.protocol
    if packet.errors:
        packet.summary += " [" + "; ".join(packet.errors) + "]"
    packet.fields["addr"] = [packet.src, packet.dst]
    packet.fields["port"] = [p for p in (packet.sport, packet.dport) if p is not None]
    packet.fields["src"] = packet.src
    packet.fields["dst"] = packet.dst
    return packet


def link_layer(packet):
    data, linktype = packet.raw.data, packet.raw.linktype
    if linktype == 1:
        require(data, 0, 14, "Ethernet")
        dst, src = data[:6].hex(":"), data[6:12].hex(":")
        packet.src, packet.dst = src, dst
        kind, offset = u16(data, 12), 14
        packet.layer("Ethernet", {"src": src, "dst": dst, "type": f"0x{kind:04x}"})
        tags = []
        while kind in (0x8100, 0x88A8, 0x9100):
            if len(tags) == 8:
                raise Malformed("VLAN 层数超过支持的 8 层")
            require(data, offset, 4, "VLAN")
            control = u16(data, offset)
            tags.append({"id": control & 4095, "priority": control >> 13, "dei": (control >> 12) & 1})
            kind = u16(data, offset + 2)
            offset += 4
        if tags:
            packet.layer("VLAN", {"tags": tags, "id": [tag["id"] for tag in tags]})
        return data[offset:], kind
    if linktype in (0, 108):
        require(data, 0, 4, "Loopback")
        family = int.from_bytes(data[:4], "little" if linktype == 0 else "big")
        packet.layer("Loopback", {"family": family, "byte_order": "little" if linktype == 0 else "big"})
        if family == 2:
            return data[4:], 0x0800
        if family in (10, 23, 24, 28, 30):
            return data[4:], 0x86DD
        packet.summary = f"未支持的 loopback 地址族 {family}"
        return b"", None
    if linktype in (12, 101, 228, 229):
        require(data, 0, 1, "Raw IP")
        version = data[0] >> 4
        if version not in (4, 6):
            raise Malformed("Raw IP 版本非法")
        packet.layer("RawIP", {"version": version})
        return data, 0x0800 if version == 4 else 0x86DD
    packet.summary = f"链路类型 {linktype} 未支持；保留原始字节"
    return b"", None


def parse_arp(packet, data):
    require(data, 0, 8, "ARP")
    hardware, protocol, hlen, plen, operation = struct.unpack_from("!HHBBH", data)
    require(data, 8, 2 * (hlen + plen), "ARP 地址")
    offset = 8
    sha, spa = data[offset:offset + hlen], data[offset + hlen:offset + hlen + plen]
    offset += hlen + plen
    tha, tpa = data[offset:offset + hlen], data[offset + hlen:offset + hlen + plen]
    packet.src = str(ipaddress.ip_address(spa)) if protocol == 0x0800 and plen == 4 else spa.hex()
    packet.dst = str(ipaddress.ip_address(tpa)) if protocol == 0x0800 and plen == 4 else tpa.hex()
    packet.layer("ARP", {"hardware": hardware, "protocol": protocol, "operation": operation,
                         "sender_mac": sha.hex(":"), "sender_ip": packet.src,
                         "target_mac": tha.hex(":"), "target_ip": packet.dst})
    packet.summary = f"ARP {operation}: {packet.src} → {packet.dst}"


def parse_ipv4(packet, data):
    require(data, 0, 20, "IPv4")
    header_length = (data[0] & 15) * 4
    total = u16(data, 2)
    if data[0] >> 4 != 4 or header_length < 20 or total < header_length:
        raise Malformed("IPv4 版本或报头/总长度非法")
    require(data, 0, header_length, "IPv4 变长报头")
    packet.src, packet.dst = str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
    fragment = u16(data, 6)
    packet.layer("IPv4", {"src": packet.src, "dst": packet.dst, "header_length": header_length,
                          "total_length": total, "id": u16(data, 4), "ttl": data[8], "protocol": data[9],
                          "fragment_offset": (fragment & 8191) * 8, "more_fragments": bool(fragment & 8192),
                          "options": options(data[20:header_length])})
    packet.fields["ip"] = True
    if total > len(data):
        packet.errors.append("IPv4 数据报被截断")
    if fragment & 0x3FFF:
        packet.fields["ip.fragmented"] = True
        packet.summary = "IPv4 分片，未执行 IP 重组"
        return
    parse_transport(packet, data[header_length:min(total, len(data))], data[9])


def parse_ipv6(packet, data):
    require(data, 0, 40, "IPv6")
    if data[0] >> 4 != 6:
        raise Malformed("IPv6 版本非法")
    length, next_header, offset = u16(data, 4), data[6], 40
    packet.src, packet.dst = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
    packet.layer("IPv6", {"src": packet.src, "dst": packet.dst, "payload_length": length,
                          "next_header": next_header, "hop_limit": data[7], "flow_label": u32(data, 0) & 0xFFFFF})
    packet.fields["ip"] = True
    if length == 0:
        packet.summary = "IPv6 空载荷或 jumbogram；未解析 jumbogram"
        return
    if 40 + length > len(data):
        packet.errors.append("IPv6 数据报被截断")
    data = data[:min(len(data), 40 + length)]
    extensions = []
    while next_header in (0, 43, 44, 51, 60):
        if len(extensions) == 16:
            raise Malformed("IPv6 扩展头超过支持的 16 层")
        require(data, offset, 2, "IPv6 扩展头")
        kind = next_header
        next_header = data[offset]
        if kind == 44:
            require(data, offset, 8, "IPv6 分片头")
            fragment = u16(data, offset + 2)
            extensions.append({"type": kind, "offset": fragment >> 3, "more": bool(fragment & 1), "id": u32(data, offset + 4)})
            packet.layers["IPv6"]["extensions"] = extensions
            if fragment & 0xFFF9:
                packet.fields["ip.fragmented"] = True
                packet.summary = "IPv6 分片，未执行 IP 重组"
                return
            size = 8
        else:
            size = (data[offset + 1] + 2) * 4 if kind == 51 else (data[offset + 1] + 1) * 8
            require(data, offset, size, "IPv6 扩展头")
            extensions.append({"type": kind, "length": size})
        offset += size
    packet.layers["IPv6"]["extensions"] = extensions
    if next_header == 50:
        packet.summary = "IPv6 ESP 加密载荷"
        return
    if next_header != 59:
        parse_transport(packet, data[offset:], next_header)


def parse_transport(packet, data, protocol):
    if protocol == 6:
        require(data, 0, 20, "TCP")
        packet.sport, packet.dport = u16(data, 0), u16(data, 2)
        length = (data[12] >> 4) * 4
        if length < 20:
            raise Malformed("TCP 数据偏移小于最小报头长度")
        require(data, 0, length, "TCP 变长报头")
        flags = ((data[12] & 1) << 8) | data[13]
        names = [name for bit, name in ((1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"), (32, "URG"), (64, "ECE"), (128, "CWR")) if flags & bit]
        packet.layer("TCP", {"srcport": packet.sport, "dstport": packet.dport, "seq": u32(data, 4),
                             "ack": u32(data, 8), "flags": flags, "flag_names": names,
                             "window": u16(data, 14), "header_length": length, "options": options(data[20:length], tcp=True)})
        packet.payload = data[length:]
        packet.summary = f"{packet.sport} → {packet.dport} {' '.join(names)} Seq={u32(data, 4)} Len={len(packet.payload)}"
        parse_tls_record(packet)
    elif protocol == 17:
        require(data, 0, 8, "UDP")
        packet.sport, packet.dport = u16(data, 0), u16(data, 2)
        length = u16(data, 4)
        if length < 8:
            raise Malformed("UDP 长度小于 8；未支持 UDP jumbogram")
        if length > len(data):
            packet.errors.append("UDP 数据报被截断")
        packet.layer("UDP", {"srcport": packet.sport, "dstport": packet.dport, "length": length})
        packet.payload = data[8:min(length, len(data))]
        packet.summary = f"{packet.sport} → {packet.dport} UDP Len={length}"
        if 53 in (packet.sport, packet.dport):
            values = parse_dns(packet.payload)
            packet.layer("DNS", values)
            packet.summary = f"DNS ID={values['id']} {'响应' if values['response'] else '查询'} {values['questions']}"
    elif protocol in (1, 58):
        require(data, 0, 4, "ICMP")
        name = "ICMP" if protocol == 1 else "ICMPv6"
        values = {"type": data[0], "code": data[1], "checksum": u16(data, 2)}
        if data[0] in ((0, 8) if protocol == 1 else (128, 129)):
            require(data, 0, 8, "ICMP Echo")
            values.update(identifier=u16(data, 4), sequence=u16(data, 6))
        packet.layer(name, values)
        packet.payload = data[8:]
        packet.summary = f"{name} Type={data[0]} Code={data[1]}"
    else:
        packet.summary = f"IP 协议编号 {protocol}，未支持的上层协议"


def dns_name(data, offset):
    labels, visited, end, expanded = [], set(), None, 0
    for _ in range(128):
        require(data, offset, 1, "DNS 名称")
        if offset in visited:
            raise Malformed("DNS 压缩指针循环")
        visited.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            require(data, offset, 2, "DNS 压缩指针")
            pointer = ((length & 63) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if length & 0xC0:
            raise Malformed("DNS 标签类型非法")
        offset += 1
        if length == 0:
            return ".".join(labels) or ".", end or offset
        require(data, offset, length, "DNS 标签")
        expanded += length + 1
        if expanded > 254:
            raise Malformed("DNS 名称超过 255 字节")
        labels.append(data[offset:offset + length].decode("ascii", errors="backslashreplace"))
        offset += length
    raise Malformed("DNS 压缩指针跳转过多")


def parse_dns(data):
    require(data, 0, 12, "DNS")
    identifier, flags, questions, answers, authority, additional = struct.unpack_from("!6H", data)
    if questions + answers + authority + additional > 512:
        raise Malformed("DNS 记录数超过支持的 512 条")
    offset, queries, records = 12, [], []
    for _ in range(questions):
        name, offset = dns_name(data, offset)
        require(data, offset, 4, "DNS 查询")
        queries.append({"name": name, "type": u16(data, offset), "class": u16(data, offset + 2)})
        offset += 4
    for section, count in (("answer", answers), ("authority", authority), ("additional", additional)):
        for _ in range(count):
            name, offset = dns_name(data, offset)
            require(data, offset, 10, "DNS 资源记录")
            kind, klass, ttl, length = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            require(data, offset, length, "DNS RDATA")
            content = data[offset:offset + length]
            if kind == 1 and length == 4 or kind == 28 and length == 16:
                value = str(ipaddress.ip_address(content))
            elif kind in (2, 5, 12):
                value, ending = dns_name(data, offset)
                if ending > offset + length:
                    raise Malformed("DNS 名称越过 RDATA 边界")
            elif kind == 15:
                require(content, 0, 3, "DNS MX")
                exchange, ending = dns_name(data, offset + 2)
                if ending > offset + length:
                    raise Malformed("DNS MX 越过 RDATA 边界")
                value = {"preference": u16(content, 0), "exchange": exchange}
            elif kind == 16:
                value, position = [], 0
                while position < len(content):
                    size = content[position]
                    position += 1
                    require(content, position, size, "DNS TXT")
                    value.append(content[position:position + size].decode("utf-8", errors="replace"))
                    position += size
            else:
                value = content.hex()
            records.append({"section": section, "name": name, "type": kind, "class": klass, "ttl": ttl, "value": value})
            offset += length
    return {"id": identifier, "response": bool(flags & 0x8000), "rcode": flags & 15,
            "truncated": bool(flags & 0x0200), "questions": queries, "records": records}


def parse_tls_record(packet):
    data = packet.payload
    if len(data) < 5 or data[0] not in (20, 21, 22, 23) or data[1:3] not in (b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"):
        return
    length = u16(data, 3)
    if not 1 <= length <= 18432:
        return
    values = {"content_type": data[0], "record_version": data[1:3].hex(), "record_length": length,
              "record_complete": len(data) >= length + 5, "source": "自研 TLS 记录头识别"}
    if data[0] == 22 and len(data) >= 9:
        values["handshake_type"] = data[5]
    packet.layer("TLS", values)
    packet.summary = f"TLS record type={data[0]} length={length}；加密应用内容不可见"
