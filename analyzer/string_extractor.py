import re


def extract_strings(file_path, min_length=4):
    with open(file_path, 'rb') as f:
        data = f.read()
        pattern = rb'[\x20-\x7E]{%d,}' % min_length
        strings = re.findall(pattern, data)
        return [s.decode('utf-8', errors='ignore') for s in strings]
