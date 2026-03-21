def find_suspicious_strings(strings):
    suspicious = [
        "cmd.exe",
        "powershell",
        "wget",
        "curl",
        "VirtualAlloc",
        "CreateRemoteThread",
        "WriteProcessMemory"
    ]

    found = []

    for s in strings:
        for keyword in suspicious:
            if keyword.lower() in s.lower():
                found.append(s)

    return list(set(found))