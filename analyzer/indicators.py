import lief # pip install lief

def get_imports(filepath: str) -> list:
    binary = lief.parse(filepath)
    if not binary:
        return []
    return [sym.name for sym in binary.imported_symbols]

SUSPICIOUS_IMPORTS = {
    "ptrace":             20,
    "fork":               8,
    "execve":             15,
    "socket":             10,
    "connect":            10,
    "mprotect":           12,
    "WriteProcessMemory": 25,
    "CreateRemoteThread": 25,
    "VirtualAlloc":       15,
    "RegOpenKeyEx":       10,
}

def calculate_suspicion_score(found_imports: list) -> int:
    score = 0
    for imp in found_imports:
        if imp in SUSPICIOUS_IMPORTS:
            score += SUSPICIOUS_IMPORTS[imp]
    return score

def find_suspicious_strings(strings):
    suspicious = [
        "cmd.exe", "powershell", "wget", "curl",
        "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory"
    ]
    found = []
    for s in strings:
        for keyword in suspicious:
            if keyword.lower() in s.lower():
                found.append(s)
    return list(set(found))