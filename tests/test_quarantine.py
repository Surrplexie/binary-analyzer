import json
import os
import tempfile

from quarantine import export_manifest_csv, read_manifest_entries


def test_read_manifest_entries_skips_bad_lines():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "manifest.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"a": 1}\n')
            f.write("not json\n")
            f.write('{"b": 2}\n')
        entries = read_manifest_entries(path)
        assert len(entries) == 2
        assert entries[0]["a"] == 1
        assert entries[1]["b"] == 2


def test_export_manifest_csv(tmp_path):
    q = tmp_path / "q"
    q.mkdir()
    manifest = q / "manifest.jsonl"
    row = {
        "timestamp_utc": "2026-01-01T00:00:00Z",
        "original_path": "a.bin",
        "quarantine_path": "q/x.quarantine",
        "sha256": "ab" * 32,
        "file_size": 1,
        "suspicion_score": 0,
        "matched_imports": ["VirtualAlloc"],
        "matched_keywords": ["cmd.exe"],
        "trigger_reason": "test",
        "status": "isolated",
        "error": None,
    }
    manifest.write_text(json.dumps(row) + "\n", encoding="utf-8")
    out = tmp_path / "out.csv"
    result = export_manifest_csv(str(q), str(out))
    assert result["exported"] is True
    assert result["rows"] == 1
    assert os.path.isfile(out)
    text = out.read_text(encoding="utf-8")
    assert "sha256" in text
    assert "risk_level" in text or "matched_imports" in text
