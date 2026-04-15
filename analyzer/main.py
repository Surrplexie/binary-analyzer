import os
import sys
import json
import csv
import argparse
import hashlib
import shutil
from datetime import datetime, timezone

from string_extractor import extract_strings
from entropy import calculate_entropy, entropy_verdict
from pe_parser import parse_pe
from indicators import find_suspicious_strings, get_imports, calculate_suspicion_score, SUSPICIOUS_IMPORTS

def print_banner():
    print("Binary Analyzer v0.2")
    print("---------------------")

def section(title):
    print(f"\n{title}")
    print("-" * len(title))

def file_info(file_path):
    size = os.path.getsize(file_path)
    section("File Info")
    print(f"Size: {size} bytes")

def detect_file_type(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)

    if magic.startswith(b"MZ"):
        return "PE (Windows Executable)"
    if magic.startswith(b"\x7fELF"):
        return "ELF (Linux Binary)"
    return "Unknown"

def classify_risk_level(suspicion_score, suspicious_count):
    if suspicion_score >= 40 or suspicious_count >= 5:
        return "HIGH"
    if suspicion_score >= 20 or suspicious_count >= 2:
        return "MEDIUM"
    return "LOW"

def sha256_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def isolate_file(file_path, quarantine_dir, suspicion_score, threshold):
    result = {
        "attempted": False,
        "performed": False,
        "path": None,
        "reason": None,
        "error": None,
    }

    result["attempted"] = True
    result["reason"] = f"suspicion_score>={threshold} (actual={suspicion_score})"

    try:
        os.makedirs(quarantine_dir, exist_ok=True)

        source_hash = sha256_file(file_path)
        original_name = os.path.basename(file_path)
        quarantine_name = f"{source_hash}_{original_name}.quarantine"
        quarantine_path = os.path.join(quarantine_dir, quarantine_name)

        if os.path.exists(quarantine_path):
            result["error"] = f"Quarantine target already exists: {quarantine_path}"
            return result

        shutil.move(file_path, quarantine_path)
        destination_hash = sha256_file(quarantine_path)
        if source_hash != destination_hash:
            result["error"] = "Hash verification failed after isolation move"
            return result

        os.chmod(quarantine_path, 0o444)

        result["performed"] = True
        result["path"] = quarantine_path
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

def append_manifest(manifest_path, results, isolation_result, threshold):
    event = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "original_path": results["file_path"],
        "quarantine_path": isolation_result["path"],
        "sha256": results["file_info"]["sha256"],
        "file_size": results["file_info"]["size_bytes"],
        "suspicion_score": results["imports"]["suspicion_score"],
        "matched_imports": results["imports"]["matched_suspicious"],
        "matched_keywords": results["suspicious_indicators"],
        "trigger_reason": f"suspicion_score>={threshold}",
        "status": "isolated" if isolation_result["performed"] else "failed",
        "error": isolation_result["error"],
    }

    with open(manifest_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def read_manifest_entries(manifest_path):
    entries = []
    if not os.path.exists(manifest_path):
        return entries

    with open(manifest_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries

def list_quarantine_files(quarantine_dir):
    if not os.path.isdir(quarantine_dir):
        return []

    files = []
    for name in sorted(os.listdir(quarantine_dir)):
        path = os.path.join(quarantine_dir, name)
        if os.path.isfile(path) and name.endswith(".quarantine"):
            size = os.path.getsize(path)
            sha256 = name.split("_", 1)[0] if "_" in name else None
            files.append({
                "name": name,
                "path": path,
                "size_bytes": size,
                "sha256": sha256,
            })
    return files

def restore_from_quarantine(quarantine_dir, sha256_prefix):
    result = {
        "attempted": True,
        "restored": False,
        "source": None,
        "destination": None,
        "error": None,
    }

    manifest_path = os.path.join(quarantine_dir, "manifest.jsonl")
    entries = read_manifest_entries(manifest_path)

    target_file = None
    for item in list_quarantine_files(quarantine_dir):
        if item["sha256"] and item["sha256"].lower().startswith(sha256_prefix.lower()):
            target_file = item
            break

    if not target_file:
        result["error"] = f"No quarantined file found for hash prefix: {sha256_prefix}"
        return result

    source_path = target_file["path"]
    source_hash = target_file["sha256"]
    destination_path = None

    for entry in reversed(entries):
        if entry.get("sha256") == source_hash and entry.get("original_path"):
            destination_path = entry["original_path"]
            break

    if not destination_path:
        result["error"] = f"No original path recorded for hash: {source_hash}"
        return result

    destination_parent = os.path.dirname(destination_path)
    if destination_parent:
        os.makedirs(destination_parent, exist_ok=True)
    if os.path.exists(destination_path):
        result["error"] = f"Destination already exists: {destination_path}"
        return result

    try:
        os.chmod(source_path, 0o666)
        shutil.move(source_path, destination_path)
        result["restored"] = True
        result["source"] = source_path
        result["destination"] = destination_path
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

def delete_from_quarantine(quarantine_dir, sha256_prefix):
    result = {
        "attempted": True,
        "deleted": False,
        "path": None,
        "error": None,
    }

    target_file = None
    for item in list_quarantine_files(quarantine_dir):
        if item["sha256"] and item["sha256"].lower().startswith(sha256_prefix.lower()):
            target_file = item
            break

    if not target_file:
        result["error"] = f"No quarantined file found for hash prefix: {sha256_prefix}"
        return result

    try:
        os.chmod(target_file["path"], 0o666)
        os.remove(target_file["path"])
        result["deleted"] = True
        result["path"] = target_file["path"]
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

def export_manifest_csv(quarantine_dir, output_path=None):
    result = {
        "attempted": True,
        "exported": False,
        "csv_path": None,
        "rows": 0,
        "error": None,
    }
    manifest_path = os.path.join(quarantine_dir, "manifest.jsonl")
    entries = read_manifest_entries(manifest_path)

    if not entries:
        result["error"] = f"No manifest entries found at: {manifest_path}"
        return result

    csv_path = output_path or os.path.join(quarantine_dir, "manifest.csv")
    fieldnames = [
        "timestamp_utc",
        "original_path",
        "quarantine_path",
        "sha256",
        "file_size",
        "suspicion_score",
        "matched_imports",
        "matched_keywords",
        "trigger_reason",
        "status",
        "error",
    ]

    try:
        parent = os.path.dirname(csv_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(csv_path, "w", encoding="utf-8", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                row = dict(entry)
                row["matched_imports"] = ",".join(entry.get("matched_imports", []))
                row["matched_keywords"] = ",".join(entry.get("matched_keywords", []))
                writer.writerow({key: row.get(key) for key in fieldnames})

        result["exported"] = True
        result["csv_path"] = csv_path
        result["rows"] = len(entries)
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

def parse_args():
    parser = argparse.ArgumentParser(description="Analyze executable binaries for RE indicators.")
    parser.add_argument("binary_file", nargs="?", help="Path to the binary file to analyze")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output machine-readable JSON instead of human-readable text",
    )
    parser.add_argument(
        "--max-strings",
        type=int,
        default=10,
        help="Number of extracted strings to preview (default: 10)",
    )
    parser.add_argument(
        "--auto-isolate",
        action="store_true",
        help="Move suspicious files to a quarantine directory for manual review",
    )
    parser.add_argument(
        "--isolate-threshold",
        type=int,
        default=25,
        help="Suspicion score threshold to trigger isolation (default: 25)",
    )
    parser.add_argument(
        "--quarantine-dir",
        default="quarantine",
        help="Directory where isolated files and manifest are stored (default: quarantine)",
    )
    parser.add_argument(
        "--list-quarantine",
        action="store_true",
        help="List files currently isolated in the quarantine directory",
    )
    parser.add_argument(
        "--restore",
        dest="restore_sha256",
        help="Restore an isolated file by SHA256 prefix from the quarantine directory",
    )
    parser.add_argument(
        "--delete-from-quarantine",
        dest="delete_sha256",
        help="Permanently delete a quarantined file by SHA256 prefix",
    )
    parser.add_argument(
        "--export-manifest-csv",
        nargs="?",
        const="",
        dest="export_manifest_csv",
        help="Export quarantine manifest.jsonl to CSV (optional output path)",
    )
    return parser.parse_args()

def build_results(file_path, max_strings):
    size = os.path.getsize(file_path)
    file_hash = sha256_file(file_path)
    file_type = detect_file_type(file_path)
    strings = extract_strings(file_path)

    imports = []
    suspicion_score = 0
    import_analysis_error = None
    try:
        imports = get_imports(file_path)
        if imports:
            suspicion_score = calculate_suspicion_score(imports)
    except Exception as e:
        import_analysis_error = str(e)

    entropy = calculate_entropy(file_path)
    verdict = entropy_verdict(entropy)

    pe_info = None
    if file_type.startswith("PE"):
        pe_info = parse_pe(file_path)
    suspicious = find_suspicious_strings(strings)
    matched_suspicious_imports = sorted(set(i for i in imports if i in SUSPICIOUS_IMPORTS))

    return {
        "file_path": file_path,
        "file_info": {
            "size_bytes": size,
            "sha256": file_hash,
        },
        "file_type": file_type,
        "strings": {
            "total_found": len(strings),
            "preview": strings[:max_strings],
        },
        "imports": {
            "count": len(imports),
            "suspicion_score": suspicion_score,
            "matched_suspicious": matched_suspicious_imports,
            "analysis_error": import_analysis_error,
        },
        "entropy": {
            "score": entropy,
            "status": verdict,
        },
        "pe_info": pe_info,
        "suspicious_indicators": suspicious[:max_strings],
        "risk": {
            "level": classify_risk_level(suspicion_score, len(suspicious)),
        },
        "isolation": {
            "attempted": False,
            "performed": False,
            "path": None,
            "reason": None,
            "error": None,
        },
    }

def print_human_results(results, max_strings):
    print_banner()
    print(f"Analyzing file: {results['file_path']}")

    section("File Info")
    print(f"Size: {results['file_info']['size_bytes']} bytes")
    print(f"SHA256: {results['file_info']['sha256']}")

    section("File Type")
    print(results["file_type"])

    section(f"Strings Found (first {max_strings})")
    for s in results["strings"]["preview"]:
        print(s)

    section("Import Analysis")
    if results["imports"]["analysis_error"]:
        print(f"Could not analyze imports: {results['imports']['analysis_error']}")
    elif results["imports"]["count"] == 0:
        print("No imports found or not a dynamic binary.")
    else:
        score = results["imports"]["suspicion_score"]
        print(f"Total Suspicion Score: {score}")
        if score > 20:
            print("[!] Warning: High number of sensitive API imports detected.")

    section("Risk Level")
    print(results["risk"]["level"])

    section("Entropy Analysis")
    print(f"Entropy Score: {results['entropy']['score']:.2f}")
    print(f"Status: {results['entropy']['status']}")

    if results["pe_info"]:
        section("PE Info")
        print(f"Architecture: {results['pe_info']['arch']}")

    section("Suspicious Indicators")
    if results["suspicious_indicators"]:
        for s in results["suspicious_indicators"]:
            print(f"[!] {s}")
    else:
        print("None found")

    if results["isolation"]["attempted"]:
        section("Isolation")
        if results["isolation"]["performed"]:
            print(f"[!] File isolated for manual review: {results['isolation']['path']}")
            print(f"Trigger: {results['isolation']['reason']}")
        else:
            print(f"Isolation failed: {results['isolation']['error']}")

def main():
    args = parse_args()
    file_path = args.binary_file
    max_strings = max(args.max_strings, 0)

    if args.list_quarantine:
        files = list_quarantine_files(args.quarantine_dir)
        if args.as_json:
            print(json.dumps({"quarantine_dir": args.quarantine_dir, "files": files}, indent=2))
            return
        print_banner()
        section("Quarantine Files")
        if not files:
            print("No isolated files found.")
            return
        for item in files:
            print(f"- {item['name']} ({item['size_bytes']} bytes)")
        return

    if args.restore_sha256:
        restore_result = restore_from_quarantine(args.quarantine_dir, args.restore_sha256)
        if args.as_json:
            print(json.dumps({"quarantine_dir": args.quarantine_dir, "restore": restore_result}, indent=2))
            return
        print_banner()
        section("Restore")
        if restore_result["restored"]:
            print(f"Restored: {restore_result['destination']}")
        else:
            print(f"Restore failed: {restore_result['error']}")
        return

    if args.delete_sha256:
        delete_result = delete_from_quarantine(args.quarantine_dir, args.delete_sha256)
        if args.as_json:
            print(json.dumps({"quarantine_dir": args.quarantine_dir, "delete": delete_result}, indent=2))
            return
        print_banner()
        section("Delete")
        if delete_result["deleted"]:
            print(f"Deleted: {delete_result['path']}")
        else:
            print(f"Delete failed: {delete_result['error']}")
        return

    if args.export_manifest_csv is not None:
        output_path = args.export_manifest_csv if args.export_manifest_csv else None
        export_result = export_manifest_csv(args.quarantine_dir, output_path)
        if args.as_json:
            print(json.dumps({"quarantine_dir": args.quarantine_dir, "export": export_result}, indent=2))
            return
        print_banner()
        section("Export Manifest CSV")
        if export_result["exported"]:
            print(f"Exported: {export_result['csv_path']} ({export_result['rows']} rows)")
        else:
            print(f"Export failed: {export_result['error']}")
        return

    if not file_path:
        print("Error: missing binary_file. Provide a file to analyze, or use quarantine commands.")
        sys.exit(1)

    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist")
        sys.exit(1)

    results = build_results(file_path, max_strings)
    if args.auto_isolate and results["imports"]["suspicion_score"] >= args.isolate_threshold:
        isolation_result = isolate_file(
            file_path=file_path,
            quarantine_dir=args.quarantine_dir,
            suspicion_score=results["imports"]["suspicion_score"],
            threshold=args.isolate_threshold,
        )
        results["isolation"] = isolation_result
        manifest_path = os.path.join(args.quarantine_dir, "manifest.jsonl")
        append_manifest(manifest_path, results, isolation_result, args.isolate_threshold)

    if args.as_json:
        print(json.dumps(results, indent=2))
        return

    print_human_results(results, max_strings)

if __name__ == "__main__":
    main()