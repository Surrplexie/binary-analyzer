import math
import os

def calculate_entropy(file_path: str) -> float:
    if not os.path.exists(file_path):
        return 0.0
    
    # Read the file bytes
    with open(file_path, 'rb') as f:
        data = f.read()

    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
            
    return round(entropy, 4)

def entropy_verdict(e: float) -> str:
    if e > 7.2: return "HIGH — likely packed/encrypted"
    if e > 6.0: return "MEDIUM — possibly compressed"
    return "NORMAL"