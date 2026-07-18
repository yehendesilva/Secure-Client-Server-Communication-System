import socket
import sys

HOST = "127.0.0.1"
PORT = 50936
MAX_PAYLOAD = 4096


def send_frame(sock: socket.socket, payload: str) -> None:
    data = payload.encode()
    if len(data) > MAX_PAYLOAD:
        raise ValueError("Payload too large")
    frame = f"LEN:{len(data)}\n".encode() + data
    sock.sendall(frame)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    received = 0
    while received < n:
        chunk = sock.recv(n - received)
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> str:
    header = b""
    while not header.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed while reading header")
        header += chunk
        if len(header) > 64:
            raise ValueError("Header too long")

    header_text = header[:-1].decode()
    if not header_text.startswith("LEN:"):
        raise ValueError("Invalid response header")

    length = int(header_text[4:])
    payload = recv_exact(sock, length)
    return payload.decode(errors="replace")


def main() -> None:
    host = HOST
    if len(sys.argv) > 1:
        host = sys.argv[1]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, PORT))
        print(f"Connected to {host}:{PORT}")
        print("Type commands like:")
        print("  REGISTER user123 pass123")
        print("  LOGIN user123 pass123")
        print("  WHOAMI <token>")
        print("  LOGOUT")
        print("  PING")
        print("Type EXIT to quit.\n")

        while True:
            cmd = input("> ").strip()
            if not cmd:
                continue
            if cmd.upper() == "EXIT":
                break

            send_frame(sock, cmd)
            response = recv_frame(sock)
            print(response)


if __name__ == "__main__":
    main()
