import argparse
import queue
import socket
import threading
import time
from contextlib import ExitStack


class HttpLab:
    def __init__(self, host="127.0.0.1", port=18080):
        if host not in ("127.0.0.1", "::1"):
            raise ValueError("教学流量工具仅允许本机 loopback 地址")
        self.host, self.port = host, port
        self.family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.server = socket.socket(self.family, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(16)
        self.server.settimeout(0.2)
        self.port = self.server.getsockname()[1]
        self.stop_event = threading.Event()
        self.errors = queue.Queue()
        self.workers = []
        self.thread = threading.Thread(target=self._accept, name="lab-http-server")

    def __enter__(self):
        self.thread.start()
        return self

    def _accept(self):
        while not self.stop_event.is_set():
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            worker = threading.Thread(target=self._serve, args=(connection,))
            self.workers.append(worker)
            worker.start()

    def _serve(self, connection):
        try:
            with connection:
                connection.settimeout(5)
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    part = connection.recv(4096)
                    if not part:
                        raise ConnectionError("HTTP 客户端在报头完成前关闭")
                    request.extend(part)
                    if len(request) > 65536:
                        raise ValueError("HTTP 测试请求超过限制")
                body = b"UCAS real HTTP response"
                header = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                connection.sendall(header[:22])
                time.sleep(0.05)
                connection.sendall(header[22:] + body)
        except Exception as error:
            self.errors.put(error)

    def exercise(self, flows=3):
        with ExitStack() as stack:
            clients = []
            for _ in range(flows):
                client = stack.enter_context(socket.socket(self.family, socket.SOCK_STREAM))
                client.settimeout(5)
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                client.connect((self.host, self.port))
                clients.append(client)
            # 保持连接，使周期性 Windows 连接表采样有真实观察窗口。
            time.sleep(0.6)
            responses = []
            for index, client in enumerate(clients):
                request = f"GET /split/{index} HTTP/1.1\r\nHost: lab.local:{self.port}\r\nConnection: close\r\n\r\n".encode()
                client.sendall(request[:22])
                time.sleep(0.05)
                client.sendall(request[22:])
                response = bytearray()
                while True:
                    part = client.recv(4096)
                    if not part:
                        break
                    response.extend(part)
                if not response.endswith(b"UCAS real HTTP response"):
                    raise RuntimeError("HTTP 测试响应内容不匹配")
                responses.append(bytes(response))
            return responses

    def __exit__(self, *args):
        self.stop_event.set()
        self.thread.join(3)
        self.server.close()
        for worker in self.workers:
            worker.join(6)
            if worker.is_alive():
                raise TimeoutError("HTTP 测试工作线程未结束")
        if not self.errors.empty():
            raise self.errors.get()


def main():
    parser = argparse.ArgumentParser(description="只产生本机真实 HTTP/1.1 流量")
    parser.add_argument("--host", choices=("127.0.0.1", "::1"), default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--flows", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.flows <= 16:
        parser.error("flows 必须为 1–16")
    with HttpLab(args.host, args.port) as lab:
        responses = lab.exercise(args.flows)
        print(f"PASS: {args.host}:{lab.port} 完成 {len(responses)} 条 TCP 流，包含跨段 HTTP 报头")


if __name__ == "__main__":
    main()
