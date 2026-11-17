import re


REQUEST = re.compile(rb"([A-Z!#$%&'*+.^_`|~-]+) ([^\x00-\x20\x7f]+) HTTP/(1\.[01])\Z")
RESPONSE = re.compile(rb"HTTP/(1\.[01]) ([0-9]{3})(?: ([^\r\n]*))?\Z")
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
MAX_HEADER = 65536
MAX_BODY = 262144


def chunked_body(data, start):
    position, preview, total = start, bytearray(), 0
    for _ in range(8192):
        end = data.find(b"\r\n", position)
        if end < 0:
            return None, bytes(preview), "chunked 长度行不完整"
        line = data[position:end].split(b";", 1)[0]
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", line):
            return None, bytes(preview), "chunked 长度非法"
        size = int(line, 16)
        position = end + 2
        if size == 0:
            if data[position:position + 2] == b"\r\n":
                return position + 2, bytes(preview), "完整"
            trailer_end = data.find(b"\r\n\r\n", position)
            if trailer_end < 0:
                return None, bytes(preview), "chunked trailer 不完整"
            for line in data[position:trailer_end].split(b"\r\n"):
                if b":" not in line or not HEADER_NAME.fullmatch(line.split(b":", 1)[0]):
                    return None, bytes(preview), "chunked trailer 非法"
            return trailer_end + 4, bytes(preview), "完整"
        total += size
        if total > MAX_BODY:
            return None, bytes(preview), "chunked 正文超过分析上限"
        if len(data) < position + size + 2:
            preview.extend(data[position:position + min(size, max(0, 4096 - len(preview)))])
            return None, bytes(preview), "chunked 数据不完整"
        if data[position + size:position + size + 2] != b"\r\n":
            return None, bytes(preview), "chunked 数据终止符非法"
        preview.extend(data[position:position + min(size, max(0, 4096 - len(preview)))])
        position += size + 2
    return None, bytes(preview), "chunked 块数超过上限"


def inspect_http(data, closed=False, request_methods=()):
    messages, position, response_index = [], 0, 0
    for _ in range(128):
        end = data.find(b"\r\n\r\n", position)
        if end < 0 or end - position > MAX_HEADER:
            break
        lines = data[position:end].split(b"\r\n")
        request, response = REQUEST.fullmatch(lines[0]), RESPONSE.fullmatch(lines[0])
        if not request and not response:
            break
        headers = {}
        valid = True
        for line in lines[1:]:
            if b":" not in line:
                valid = False
                break
            name, value = line.split(b":", 1)
            if not HEADER_NAME.fullmatch(name) or any(byte < 32 and byte != 9 for byte in value):
                valid = False
                break
            key = name.decode("ascii").lower()
            headers.setdefault(key, []).append(value.strip().decode("iso-8859-1"))
        if not valid:
            break
        message = {"headers": headers, "start": position, "header_end": end + 4,
                   "host": ", ".join(headers.get("host", [])), "source": "自研 TCP 重组与 HTTP/1.x 分析"}
        if request:
            message.update(method=request[1].decode("ascii"), path=request[2].decode("iso-8859-1"), version=request[3].decode())
        else:
            message.update(status=int(response[2]), version=response[1].decode(), reason=(response[3] or b"").decode("iso-8859-1"))
        body_start, next_position, preview, state = end + 4, None, b"", "完整"
        transfer = ",".join(headers.get("transfer-encoding", [])).lower()
        lengths = headers.get("content-length", [])
        method = request_methods[response_index] if response and response_index < len(request_methods) else None
        no_body = response and (100 <= message["status"] < 200 or message["status"] in (204, 304) or method == "HEAD")
        tunnel = response and ((method == "CONNECT" and 200 <= message["status"] < 300) or message["status"] == 101)
        if transfer and lengths:
            state = "Transfer-Encoding 与 Content-Length 同时出现，边界有歧义"
        elif no_body:
            next_position = body_start
        elif transfer:
            if transfer.strip() == "chunked":
                next_position, preview, state = chunked_body(data, body_start)
            else:
                state = "未支持的 Transfer-Encoding"
        elif lengths:
            if len(set(lengths)) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
                state = "Content-Length 非法或冲突"
            else:
                length = int(lengths[0])
                preview = data[body_start:body_start + min(length, 4096)]
                if length > MAX_BODY:
                    state = "正文超过分析上限"
                elif len(data) < body_start + length:
                    state = "Content-Length 正文不完整"
                else:
                    next_position = body_start + length
        elif request:
            next_position = body_start
        else:
            preview = data[body_start:body_start + 4096]
            next_position = len(data) if closed else None
            state = "完整（连接关闭定界）" if closed else "等待连接关闭定界"
        if tunnel:
            next_position = None
            state = "协议切换，HTTP 分析在此停止"
        message.update(body_preview=preview.decode("utf-8", errors="replace"), body_state=state,
                       complete=next_position is not None, end=next_position)
        messages.append(message)
        if response and not 100 <= message["status"] < 200:
            response_index += 1
        if next_position is None or next_position <= position:
            break
        position = next_position
        if position == len(data):
            break
    return messages
