import argparse
import socket
import struct
import threading
import time


MAGIC = b"LAB1"
PORT = 45990
HEADER = struct.Struct("!4sBBIH")


def encode(message_type, request_id, payload):
    if message_type not in (1, 2, 3) or not 0 <= request_id <= 0xFFFFFFFF or len(payload) > 4096:
        raise ValueError("LABDEMO 参数超出协议范围")
    return HEADER.pack(MAGIC, 1, message_type, request_id, len(payload)) + payload


def decode(data):
    if len(data) < 4 or data[:4] != MAGIC:
        return None
    if len(data) < HEADER.size:
        return {"valid": False, "error": "header_truncated"}
    magic, version, message_type, identifier, length = HEADER.unpack_from(data)
    result = {"version": version, "type": message_type, "request_id": identifier, "length": length}
    error = ""
    if version != 1:
        error = "unsupported_version"
    elif length > 4096 or len(data) != HEADER.size + length:
        error = "invalid_length"
    elif message_type not in (1, 2, 3):
        error = "unknown_type"
    result.update(valid=not error, error=error, payload=data[HEADER.size:].decode("utf-8", errors="replace"))
    return result


class DemoServer:
    def __init__(self, host="127.0.0.1", port=PORT):
        if host not in ("127.0.0.1", "::1"):
            raise ValueError("教学服务器只允许绑定本机 loopback")
        self.socket = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((host, port))
        self.socket.settimeout(0.1)
        self.host, self.port = host, self.socket.getsockname()[1]
        self.event = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._run, name="labdemo-server")

    def _run(self):
        try:
            while not self.event.is_set():
                try:
                    data, address = self.socket.recvfrom(8192)
                except socket.timeout:
                    continue
                message = decode(data)
                if message is None:
                    continue
                if message.get("error") == "unknown_type":
                    self.socket.sendto(encode(3, message["request_id"], b"unknown type"), address)
                elif message["valid"] and message["type"] == 1:
                    if message["payload"] == "timeout":
                        continue
                    self.socket.sendto(encode(2, message["request_id"], b"ACK:" + data[HEADER.size:]), address)
        except Exception as error:
            self.error = error

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.event.set()
        self.thread.join(2)
        self.socket.close()
        if self.thread.is_alive():
            raise TimeoutError("LABDEMO 服务未停止")
        if self.error:
            raise self.error


def exercise(host="127.0.0.1", port=PORT):
    if host not in ("127.0.0.1", "::1"):
        raise ValueError("教学客户端只允许连接本机 loopback")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(encode(1, 1001, b"hello"), (host, port))
        response = decode(client.recvfrom(8192)[0])
        if not response or not response["valid"] or response["type"] != 2 or response["request_id"] != 1001:
            raise RuntimeError("LABDEMO 正常响应验证失败")
        client.sendto(b"BAD!" + encode(1, 1002, b"bad")[4:], (host, port))
        client.sendto(HEADER.pack(MAGIC, 1, 1, 1003, 100) + b"bad", (host, port))
        client.sendto(HEADER.pack(MAGIC, 1, 99, 1004, 0), (host, port))
        error = decode(client.recvfrom(8192)[0])
        if not error or error["type"] != 3 or error["request_id"] != 1004:
            raise RuntimeError("LABDEMO 错误响应验证失败")
        client.sendto(encode(1, 1005, b"timeout"), (host, port))
        time.sleep(2.1)
        client.sendto(encode(1, 1006, b"last"), (host, port))
        last = decode(client.recvfrom(8192)[0])
        if not last or last["request_id"] != 1006:
            raise RuntimeError("LABDEMO 最后响应验证失败")
        return {"normal": response, "error": error, "last": last}


def main():
    parser = argparse.ArgumentParser(description="LABDEMO 本机 UDP 教学协议")
    parser.add_argument("mode", choices=("server", "client", "exercise"))
    parser.add_argument("--host", choices=("127.0.0.1", "::1"), default="127.0.0.1")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    if args.mode == "server":
        with DemoServer(args.host, args.port):
            print(f"LABDEMO 服务 {args.host}:{args.port}；按 Ctrl+C 结束", flush=True)
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                return
    elif args.mode == "client":
        print(exercise(args.host, args.port))
    else:
        with DemoServer(args.host, args.port):
            print(exercise(args.host, args.port))


if __name__ == "__main__":
    main()
