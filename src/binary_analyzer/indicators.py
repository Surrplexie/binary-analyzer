try:
    import lief  # pip install lief
except ImportError:
    lief = None

def get_imports(filepath: str) -> list:
    if lief is None:
        raise RuntimeError("lief is not installed. Install it with: pip install lief")
    binary = lief.parse(filepath)
    if not binary:
        return []

    # LIEF APIs differ by binary format and version.
    # Prefer imported_symbols when available, then fallback to PE import entries.
    if hasattr(binary, "imported_symbols"):
        return [sym.name for sym in binary.imported_symbols if getattr(sym, "name", None)]

    if hasattr(binary, "imports"):
        imports = []
        for lib in binary.imports:
            for entry in getattr(lib, "entries", []):
                name = getattr(entry, "name", None)
                if name:
                    imports.append(name)
        return imports

    return []

def calculate_suspicion_score(found_imports: list, suspicious_imports: dict[str, int]) -> int:
    score = 0
    for imp in found_imports:
        if imp in suspicious_imports:
            score += suspicious_imports[imp]
    return score


def find_suspicious_strings(strings, keywords: list[str]):
    found = []
    for s in strings:
        for keyword in keywords:
            if keyword.lower() in s.lower():
                found.append(s)
    return list(set(found))
