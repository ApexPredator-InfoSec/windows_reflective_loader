import socket
import struct
import argparse



def main():
    parser = argparse.ArgumentParser(description="EXE sender")
    parser.add_argument("-i","--ip", help="IP to bind or 0.0.0.0", required=True)
    parser.add_argument("-p","--port", type=int, help="Port to listen on", required=True)
    parser.add_argument("-f", "--file_path", help="Path to EXE binary", required=True)
    args = parser.parse_args()
    # Load EXE binary
    with open(args.file_path, 'rb') as f:
        exe_data = f.read()

    exe_size = len(exe_data)
    print(f"[+] Loaded EXE binary ({exe_size} bytes)")

    # Create socket and bind
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.ip, args.port))
        s.listen(1)
        print(f"[+] Listening on {args.ip}:{args.port}...")

        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")

            # Send 4-byte little-endian size prefix
            conn.sendall(struct.pack('<I', exe_size))

            # Send EXE binary
            conn.sendall(exe_data)
            print(f"[+] Sent {exe_size} bytes")

if __name__ == '__main__':
    main()
