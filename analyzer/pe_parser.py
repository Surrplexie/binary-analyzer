import struct


def parse_pe(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    if data[:2] != b'MZ':
        return None

    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]

    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return None

    machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]

    arch = "Unknown"
    if machine == 0x14c:
        arch = "x86"
    elif machine == 0x8664:
        arch = "x64"

    # Number of sections
    num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]

    optional_header_size = struct.unpack("<H", data[pe_offset+20:pe_offset+22])[0]

    section_table_offset = pe_offset + 24 + optional_header_size

    sections = []

    for i in range(num_sections):
        offset = section_table_offset + (40 * i)

        name = data[offset:offset+8].strip(b'\x00').decode(errors="ignore")
        raw_size = struct.unpack("<I", data[offset+16:offset+20])[0]
        raw_ptr = struct.unpack("<I", data[offset+20:offset+24])[0]

        sections.append({
            "name": name,
            "size": raw_size,
            "offset": raw_ptr
        })

    return {
        "arch": arch,
        "sections": sections
    }