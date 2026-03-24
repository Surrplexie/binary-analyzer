import math

def calculate_entropy_bytes(data):
    import math

    if not data:
        return 0

    entropy = 0
    byte_counts = [0] * 256

    for byte in data:
        byte_counts[byte] += 1

    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)

    return entropy

