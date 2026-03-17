import struct

def parse_pe(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    # Check DOS header
    if data[:2] != b'MZ':
        return None

    # Get PE header offset
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]

    # Check PE signature
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return None

    # Machine type
    machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]

    arch = "Unknown"
    if machine == 0x14c:
        arch = "x86"
    elif machine == 0x8664:
        arch = "x64"

    return {
        "arch": arch,
        "pe_offset": pe_offset
    }