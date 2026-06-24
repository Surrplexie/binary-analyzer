import argparse
import json
import os
import sys

from .analysis import build_results, build_results_with_unpack
from .rules import load_effective_rules, RULES_ENV_VAR
from .quarantine import (
    append_manifest,
    delete_from_quarantine,
    export_manifest_csv,
    isolate_file,
    list_quarantine_files,
    restore_from_quarantine,
)
from .risk import risk_meets_minimum


def print_banner():
    print("Binary Analyzer v0.2")
    print("---------------------")


def section(title):
    print(f"\n{title}")
    print("-" * len(title))


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
        "--isolate-on-risk",
        choices=["LOW", "MEDIUM", "HIGH"],
        default=None,
        help="Also isolate when computed risk level is at or above this (e.g. MEDIUM isolates MEDIUM and HIGH)",
    )
    parser.add_argument(
        "--keyword-isolate-threshold",
        type=int,
        default=0,
        help="Also isolate when suspicious string hit count >= N (0 disables)",
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
    parser.add_argument(
        "--rules",
        default=None,
        metavar="PATH",
        help=f"JSON rules file (import weights, string keywords, risk bands). "
        f"Overrides {RULES_ENV_VAR} when set.",
    )
    parser.add_argument(
        "--detect-packers",
        action="store_true",
        help="Detect common executable packers (UPX first) and include results in output",
    )
    parser.add_argument(
        "--unpack",
        action="store_true",
        help="Attempt to unpack detected packers, re-hash, and produce a before/after report",
    )
    parser.add_argument(
        "--unpack-output",
        default=None,
        metavar="DIR",
        help="Directory for unpacked dumps (default: temporary directory)",
    )
    return parser.parse_args()


def isolation_triggers(args, results):
    parts = []
    score = results["imports"]["suspicion_score"]
    level = results["risk"]["level"]
    total_kw = results["suspicious_indicators_total"]

    if score >= args.isolate_threshold:
        parts.append(f"suspicion_score>={args.isolate_threshold} (actual={score})")
    if args.isolate_on_risk and risk_meets_minimum(level, args.isolate_on_risk):
        parts.append(f"risk>={args.isolate_on_risk} (actual={level})")
    if args.keyword_isolate_threshold > 0 and total_kw >= args.keyword_isolate_threshold:
        parts.append(f"suspicious_strings_count>={args.keyword_isolate_threshold} (actual={total_kw})")

    if not parts:
        return False, None
    return True, "; ".join(parts)


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


def print_packer_results(results):
    packer = results.get("packer")
    if not packer:
        return

    section("Packer Detection")
    detected = packer.get("detected", [])
    if not detected:
        print("No known packers detected.")
    else:
        for match in detected:
            signals = ", ".join(match["signals"])
            print(f"[!] {match['name']} ({match['confidence']} confidence) — {signals}")

    unpack = packer.get("unpack", {})
    if unpack.get("attempted") or unpack.get("error"):
        section("Unpack")
        if unpack.get("performed"):
            print(f"Method: {unpack['method']}")
            print(f"Output: {unpack['output_path']}")
            print(f"Unpacked SHA256: {unpack['sha256']}")
        elif unpack.get("attempted"):
            print(f"Unpack failed: {unpack.get('error')}")
        elif unpack.get("error"):
            print(unpack["error"])


def print_comparison_results(comparison):
    if not comparison:
        return

    section("Before / After Comparison")
    print(f"SHA256 changed: {comparison['sha256_changed']}")
    print(f"Size delta: {comparison['size_delta_bytes']:+d} bytes")
    print(f"Entropy delta: {comparison['entropy_delta']:+.2f}")
    print(f"Risk: {comparison['risk_before']} -> {comparison['risk_after']}")
    print(
        "Suspicious indicators: "
        f"{comparison['suspicious_indicators_before']} -> "
        f"{comparison['suspicious_indicators_after']} "
        f"({comparison['suspicious_indicators_delta']:+d})"
    )
    if comparison["imports_added"]:
        print("Imports added (suspicious matches):")
        for item in comparison["imports_added"]:
            print(f"  + {item}")
    if comparison["imports_removed"]:
        print("Imports removed (suspicious matches):")
        for item in comparison["imports_removed"]:
            print(f"  - {item}")


def print_human_unpack_results(results, max_strings):
    before = results["analysis"]["before"]
    print_human_results(before, max_strings)
    print_packer_results(results)
    print_comparison_results(results.get("comparison"))
    after = results["analysis"].get("after")
    if after:
        section("After Unpack Analysis")
        print(f"File: {after['file_path']}")
        print(f"Size: {after['file_info']['size_bytes']} bytes")
        print(f"SHA256: {after['file_info']['sha256']}")
        print(f"Risk: {after['risk']['level']}")
        print(f"Entropy: {after['entropy']['score']:.2f} ({after['entropy']['status']})")
        print(f"Imports: {after['imports']['count']}")


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

    rules = load_effective_rules(cli_path=args.rules)
    use_packer_pipeline = args.detect_packers or args.unpack

    if use_packer_pipeline:
        results = build_results_with_unpack(
            file_path,
            max_strings,
            rules=rules,
            detect_packers_flag=True,
            unpack=args.unpack,
            unpack_output_dir=args.unpack_output,
        )
        analysis_for_isolation = results["analysis"]["before"]
    else:
        results = build_results(file_path, max_strings, rules=rules)
        analysis_for_isolation = results

    if args.auto_isolate:
        should, reason = isolation_triggers(args, analysis_for_isolation)
        if should:
            isolation_result = isolate_file(
                file_path=file_path,
                quarantine_dir=args.quarantine_dir,
                sha256_hex=analysis_for_isolation["file_info"]["sha256"],
                trigger_reason=reason,
            )
            if use_packer_pipeline:
                results["analysis"]["before"]["isolation"] = isolation_result
            else:
                results["isolation"] = isolation_result
            manifest_path = os.path.join(args.quarantine_dir, "manifest.jsonl")
            append_manifest(manifest_path, analysis_for_isolation, isolation_result, reason)

    if args.as_json:
        print(json.dumps(results, indent=2))
        return

    if use_packer_pipeline:
        print_human_unpack_results(results, max_strings)
        return

    print_human_results(results, max_strings)


if __name__ == "__main__":
    main()
