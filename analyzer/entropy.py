import math

def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    if not data:
        return 0

    byte_counts = [0] * 256

    for byte in data:
        byte_counts[byte] += 1

    entropy = 0
    data_len = len(data)

    for count in byte_counts:
        if count == 0:
            continue
        p = count / data_len
        entropy -= p * math.log2(p)

    return entropy