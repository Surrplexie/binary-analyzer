import csv
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone


def sha256_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def isolate_file(file_path, quarantine_dir, sha256_hex, trigger_reason):
    result = {
        "attempted": False,
        "performed": False,
        "path": None,
        "reason": None,
        "error": None,
    }

    result["attempted"] = True
    result["reason"] = trigger_reason

    try:
        os.makedirs(quarantine_dir, exist_ok=True)

        original_name = os.path.basename(file_path)
        quarantine_name = f"{sha256_hex}_{original_name}.quarantine"
        quarantine_path = os.path.join(quarantine_dir, quarantine_name)

        if os.path.exists(quarantine_path):
            result["error"] = f"Quarantine target already exists: {quarantine_path}"
            return result

        shutil.move(file_path, quarantine_path)
        destination_hash = sha256_file(quarantine_path)
        if sha256_hex != destination_hash:
            result["error"] = "Hash verification failed after isolation move"
            return result

        os.chmod(quarantine_path, 0o444)

        result["performed"] = True
        result["path"] = quarantine_path
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def append_manifest(manifest_path, results, isolation_result, trigger_reason):
    event = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "original_path": results["file_path"],
        "quarantine_path": isolation_result["path"],
        "sha256": results["file_info"]["sha256"],
        "file_size": results["file_info"]["size_bytes"],
        "suspicion_score": results["imports"]["suspicion_score"],
        "risk_level": results["risk"]["level"],
        "matched_imports": results["imports"]["matched_suspicious"],
        "matched_keywords": results.get("suspicious_indicators_all", results["suspicious_indicators"]),
        "trigger_reason": trigger_reason,
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
        "risk_level",
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
