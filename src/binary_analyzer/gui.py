"""
HUD-style GUI for binary-analyzer.

Launch with:
    python -m binary_analyzer --gui
    python -m binary_analyzer.gui
Or via the standalone binary:
    binary-analyzer-gui.exe   (Windows)
    binary-analyzer-gui       (Linux)
"""
from __future__ import annotations

import json
import os
import platform
import threading
import tkinter as tk
from tkinter import filedialog, simpledialog
from pathlib import Path
from typing import Optional

try:
    import customtkinter as ctk
except ImportError as exc:
    raise ImportError(
        "GUI requires customtkinter.\n"
        "Install with:  pip install -e \".[gui]\""
    ) from exc

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES as _DND_FILES
    _HAS_DND = True
except ImportError:
    _HAS_DND = False

from .analysis import build_results
from .rules import load_effective_rules
from .quarantine import isolate_file, append_manifest


# ── Palette ───────────────────────────────────────────────────────────────────

BG        = "#0d0d1a"
BG2       = "#13132b"
BG3       = "#1c1c3a"
BG_HOVER  = "#22224a"
BG_CARD   = "#181834"
ACCENT    = "#00c8ff"
ACCENT_DK = "#007799"
TEXT      = "#dde0f0"
TEXT_DIM  = "#7788aa"
TEXT_MONO = "#a0e8b0"
BORDER    = "#2a2a5a"
RISK_HIGH = "#ff2244"
RISK_MED  = "#ff8800"
RISK_LOW  = "#00cc66"
RISK_H_BG = "#2a0010"
RISK_M_BG = "#2a1500"
RISK_L_BG = "#001a10"
GREEN_ACC = "#00cc66"
RED_ACC   = "#ff4455"

_IS_WIN = platform.system() == "Windows"
MONO    = ("Consolas" if _IS_WIN else "Monospace", 11)
MONO_SM = ("Consolas" if _IS_WIN else "Monospace", 10)
UI      = "Segoe UI" if _IS_WIN else "Ubuntu"


# ── DnD-capable root ──────────────────────────────────────────────────────────

if _HAS_DND:
    class _AppBase(ctk.CTk, TkinterDnD.DnDWrapper):  # type: ignore[misc]
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.TkdndVersion = TkinterDnD._require(self)
else:
    _AppBase = ctk.CTk  # type: ignore[assignment,misc]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def _risk_colors(level: str) -> tuple[str, str]:
    """Return (fg, bg) for a risk badge."""
    return {
        "HIGH":   (RISK_HIGH, RISK_H_BG),
        "MEDIUM": (RISK_MED,  RISK_M_BG),
    }.get(level, (RISK_LOW, RISK_L_BG))


def _strip_dnd_path(raw: str) -> str:
    return raw.strip().strip("{}")


# ── Drop-zone widget ──────────────────────────────────────────────────────────

class DropZone(ctk.CTkFrame):
    def __init__(self, master, on_file_cb, **kwargs):
        kwargs.setdefault("fg_color", BG3)
        kwargs.setdefault("border_color", ACCENT_DK)
        kwargs.setdefault("border_width", 2)
        kwargs.setdefault("corner_radius", 10)
        super().__init__(master, **kwargs)
        self._on_file = on_file_cb

        icon = ctk.CTkLabel(self, text="⬇", font=(UI, 30), text_color=ACCENT)
        icon.pack(pady=(16, 2))

        main_txt = "Drop file here" if _HAS_DND else "Click to browse"
        lbl = ctk.CTkLabel(self, text=main_txt, font=(UI, 13, "bold"), text_color=TEXT)
        lbl.pack()

        sub_txt = "or click to open file browser" if _HAS_DND else "Select a PE or ELF binary to analyze"
        sub = ctk.CTkLabel(self, text=sub_txt, font=(UI, 10), text_color=TEXT_DIM)
        sub.pack(pady=(2, 16))

        for w in (self, icon, lbl, sub):
            w.bind("<Button-1>", self._browse)
            w.bind("<Enter>", lambda _: self.configure(fg_color=BG_HOVER))
            w.bind("<Leave>", lambda _: self.configure(fg_color=BG3))

        if _HAS_DND:
            self.drop_target_register(_DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)

    def _browse(self, _=None):
        path = filedialog.askopenfilename(
            title="Select binary",
            filetypes=[
                ("Executables", "*.exe *.dll *.bin *.so *.elf"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._on_file(path)

    def _on_drop(self, event):
        path = _strip_dnd_path(event.data)
        if path and os.path.isfile(path):
            self._on_file(path)


# ── Main application ──────────────────────────────────────────────────────────

class App(_AppBase):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title("Binary Analyzer")
        self.geometry("980x720")
        self.minsize(820, 560)
        self.configure(fg_color=BG)

        self._results: Optional[dict] = None
        self._path_var = tk.StringVar()
        self._active_rules = None

        self._build_ui()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_input_area()
        ctk.CTkFrame(self, fg_color=BORDER, height=1, corner_radius=0).pack(fill="x")
        self._results_outer = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self._results_outer.pack(fill="both", expand=True)
        self._build_status_bar()
        self._show_placeholder()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=BG2, corner_radius=0, height=46)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        ctk.CTkLabel(hdr, text=" ◈  BINARY ANALYZER",
                     font=(UI, 15, "bold"), text_color=ACCENT).pack(side="left", padx=14)
        ctk.CTkLabel(hdr, text="static analysis  |  PE & ELF",
                     font=(UI, 10), text_color=TEXT_DIM).pack(side="left")

        self._rules_lbl = ctk.CTkLabel(hdr, text="rules: default",
                                        font=(UI, 10), text_color=TEXT_DIM)
        self._rules_lbl.pack(side="right", padx=14)

        ctk.CTkButton(
            hdr, text="Load Rules…", font=(UI, 10),
            fg_color="transparent", hover_color=BG3,
            border_color=BORDER, border_width=1,
            text_color=TEXT_DIM, height=26, width=96,
            command=self._load_rules,
        ).pack(side="right", padx=(0, 6))

    def _build_input_area(self):
        inp = ctk.CTkFrame(self, fg_color=BG2, corner_radius=0)
        inp.pack(fill="x", pady=(1, 0))
        inner = ctk.CTkFrame(inp, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=12)

        DropZone(inner, on_file_cb=self._load_file, height=96).pack(fill="x")

        path_row = ctk.CTkFrame(inner, fg_color="transparent")
        path_row.pack(fill="x", pady=(10, 0))

        ctk.CTkLabel(path_row, text="Path:", font=(UI, 11), text_color=TEXT_DIM).pack(side="left")

        self._path_entry = ctk.CTkEntry(
            path_row, textvariable=self._path_var,
            placeholder_text="C:\\path\\to\\binary.exe  (or paste and press Enter)",
            fg_color=BG3, border_color=BORDER, text_color=TEXT, font=MONO_SM,
        )
        self._path_entry.pack(side="left", fill="x", expand=True, padx=8)
        self._path_entry.bind("<Return>", lambda _: self._analyze())

        self._analyze_btn = ctk.CTkButton(
            path_row, text="▶  Analyze",
            font=(UI, 11, "bold"),
            fg_color=ACCENT_DK, hover_color=ACCENT, text_color=BG,
            width=116, height=32,
            command=self._analyze,
        )
        self._analyze_btn.pack(side="left")

    def _build_status_bar(self):
        sb = ctk.CTkFrame(self, fg_color=BG2, corner_radius=0, height=24)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._status_lbl = ctk.CTkLabel(sb, text="Ready — drop a file or enter a path above.",
                                         font=(UI, 10), text_color=TEXT_DIM)
        self._status_lbl.pack(side="left", padx=12)
        dnd = "Drag-and-drop active" if _HAS_DND else "Click to browse (pip install tkinterdnd2 for drag-and-drop)"
        ctk.CTkLabel(sb, text=dnd, font=(UI, 10), text_color=TEXT_DIM).pack(side="right", padx=12)

    # ── Placeholder / loading ─────────────────────────────────────────────────

    def _clear_results(self):
        for w in self._results_outer.winfo_children():
            w.destroy()

    def _show_placeholder(self):
        self._clear_results()
        ctk.CTkLabel(
            self._results_outer,
            text="No file loaded.\nDrop a binary above, or enter a path and press Analyze.",
            font=(UI, 12), text_color=TEXT_DIM,
        ).place(relx=0.5, rely=0.5, anchor="center")

    def _show_loading(self):
        self._clear_results()
        bar = ctk.CTkProgressBar(self._results_outer, mode="indeterminate",
                                  progress_color=ACCENT, width=400)
        bar.place(relx=0.5, rely=0.5, anchor="center")
        bar.start()

    # ── Analysis flow ─────────────────────────────────────────────────────────

    def _load_file(self, path: str):
        self._path_var.set(path)
        self._analyze()

    def _analyze(self):
        path = self._path_var.get().strip().strip('"')
        if not path:
            return self._set_status("Enter a file path or use the drop zone.", error=True)
        if not os.path.isfile(path):
            return self._set_status(f"File not found: {path}", error=True)

        self._analyze_btn.configure(state="disabled", text="Analyzing…")
        self._set_status(f"Analyzing  {Path(path).name} …")
        self._show_loading()

        rules = self._active_rules or load_effective_rules()
        src = getattr(rules, "source", "default")
        self._rules_lbl.configure(
            text=f"rules: {Path(src).name if src != 'package-default' else 'default'}"
        )

        def worker():
            try:
                res = build_results(path, max_strings=100, rules=rules)
                self.after(0, lambda: self._on_done(res, None))
            except Exception as exc:
                msg = str(exc)
                self.after(0, lambda: self._on_done(None, msg))

        threading.Thread(target=worker, daemon=True).start()

    def _on_done(self, results: Optional[dict], error: Optional[str]):
        self._analyze_btn.configure(state="normal", text="▶  Analyze")
        if error:
            self._show_placeholder()
            return self._set_status(f"Error: {error}", error=True)
        self._results = results
        r = results
        self._set_status(
            f"{Path(r['file_path']).name}  ·  "
            f"Risk: {r['risk']['level']}  ·  "
            f"Score: {r['imports']['suspicion_score']}  ·  "
            f"SHA256: {r['file_info']['sha256'][:16]}…"
        )
        self._render_results(r)

    # ── Results rendering ─────────────────────────────────────────────────────

    def _render_results(self, r: dict):
        self._clear_results()

        scroll = ctk.CTkScrollableFrame(
            self._results_outer, fg_color=BG,
            scrollbar_button_color=BG3,
            scrollbar_button_hover_color=ACCENT_DK,
        )
        scroll.pack(fill="both", expand=True)

        # Row 1 — file info + risk
        row1 = ctk.CTkFrame(scroll, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(14, 6))
        row1.grid_columnconfigure(0, weight=3)
        row1.grid_columnconfigure(1, weight=1)
        self._card_file_info(row1, r)
        self._card_risk(row1, r)

        # Row 2 — entropy + PE
        row2 = ctk.CTkFrame(scroll, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(0, 6))
        row2.grid_columnconfigure(0, weight=1)
        row2.grid_columnconfigure(1, weight=1)
        self._card_entropy(row2, r)
        if r.get("pe_info"):
            self._card_pe(row2, r)
        else:
            ctk.CTkFrame(row2, fg_color="transparent").grid(row=0, column=1)

        # Imports
        self._section_imports(scroll, r)

        # Suspicious strings
        if r["suspicious_indicators_all"]:
            self._section_strings(scroll, r)
        else:
            self._sep(scroll, f"Strings — {r['strings']['total_found']} extracted, none suspicious")

        # Actions
        self._action_bar(scroll, r)

    # ── Cards ─────────────────────────────────────────────────────────────────

    def _mk_card(self, parent, **kw) -> ctk.CTkFrame:
        kw.setdefault("fg_color", BG_CARD)
        kw.setdefault("border_color", BORDER)
        kw.setdefault("border_width", 1)
        kw.setdefault("corner_radius", 8)
        return ctk.CTkFrame(parent, **kw)

    def _card_header(self, card, text: str):
        ctk.CTkLabel(card, text=f"  {text}", font=(UI, 9, "bold"),
                     text_color=ACCENT).pack(anchor="w", padx=10, pady=(10, 5))

    def _kv(self, parent, label: str, value: str, mono=False):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=12, pady=1)
        ctk.CTkLabel(f, text=label, font=(UI, 10), text_color=TEXT_DIM,
                     anchor="w", width=120).pack(side="left")
        ctk.CTkLabel(f, text=value,
                     font=MONO_SM if mono else (UI, 10),
                     text_color=TEXT_MONO if mono else TEXT,
                     anchor="w", wraplength=560).pack(side="left", padx=(2, 0))

    def _card_file_info(self, parent, r: dict):
        card = self._mk_card(parent)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self._card_header(card, "FILE INFORMATION")
        self._kv(card, "Name", Path(r["file_path"]).name)
        self._kv(card, "Directory", str(Path(r["file_path"]).parent))
        self._kv(card, "Type", r["file_type"])
        self._kv(card, "Size", _fmt_bytes(r["file_info"]["size_bytes"]))
        self._kv(card, "SHA-256", r["file_info"]["sha256"], mono=True)
        ctk.CTkFrame(card, fg_color="transparent", height=8).pack()

    def _card_risk(self, parent, r: dict):
        level = r["risk"]["level"]
        fg, bg = _risk_colors(level)
        card = self._mk_card(parent, fg_color=bg, border_color=fg)
        card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self._card_header(card, "RISK ASSESSMENT")
        ctk.CTkLabel(card, text=level, font=(UI, 38, "bold"), text_color=fg).pack(pady=(2, 0))
        ctk.CTkLabel(card, text=f"import score  {r['imports']['suspicion_score']}",
                     font=MONO_SM, text_color=TEXT_DIM).pack()
        ctk.CTkLabel(card, text=f"string hits   {r['suspicious_indicators_total']}",
                     font=MONO_SM, text_color=TEXT_DIM).pack(pady=(0, 14))

    def _card_entropy(self, parent, r: dict):
        e = r["entropy"]
        card = self._mk_card(parent)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self._card_header(card, "ENTROPY")
        color = RISK_HIGH if "HIGH" in e["status"] else (RISK_MED if "MEDIUM" in e["status"] else RISK_LOW)
        ctk.CTkLabel(card, text=f"{e['score']:.4f}", font=(UI, 26, "bold"), text_color=color).pack(pady=(0, 2))
        ctk.CTkLabel(card, text=e["status"], font=(UI, 10), text_color=TEXT_DIM).pack(pady=(0, 12))

    def _card_pe(self, parent, r: dict):
        pe = r["pe_info"]
        card = self._mk_card(parent)
        card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self._card_header(card, "PE INFORMATION")
        self._kv(card, "Architecture", pe.get("arch", "Unknown"))
        secs = pe.get("sections", [])
        self._kv(card, "Sections", str(len(secs)))
        for s in secs[:5]:
            self._kv(card, f"  {s['name']}", f"{_fmt_bytes(s['size'])}  @ {hex(s['offset'])}", mono=True)
        if len(secs) > 5:
            ctk.CTkLabel(card, text=f"  … {len(secs) - 5} more sections",
                         font=(UI, 10), text_color=TEXT_DIM).pack(anchor="w", padx=14)
        ctk.CTkFrame(card, fg_color="transparent", height=8).pack()

    # ── Sections ──────────────────────────────────────────────────────────────

    def _sep(self, parent, title: str):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(f, text=title, font=(UI, 11, "bold"), text_color=ACCENT).pack(side="left")
        ctk.CTkFrame(f, fg_color=BORDER, height=1).pack(
            side="left", fill="x", expand=True, padx=(10, 0), pady=6)

    def _section_imports(self, parent, r: dict):
        imp = r["imports"]
        matched = imp["matched_suspicious"]
        self._sep(parent,
                  f"Import Analysis  —  {imp['count']} imports  ·  "
                  f"score {imp['suspicion_score']}  ·  {len(matched)} suspicious")

        if imp.get("analysis_error"):
            ctk.CTkLabel(parent, text=f"  ⚠  {imp['analysis_error']}",
                         font=(UI, 10), text_color=RISK_MED).pack(anchor="w", padx=28)
            return

        if not matched:
            ctk.CTkLabel(parent, text="  No suspicious imports detected.",
                         font=(UI, 10), text_color=TEXT_DIM).pack(anchor="w", padx=28)
            return

        card = self._mk_card(parent)
        card.pack(fill="x", padx=16, pady=(0, 4))

        try:
            weights = (self._active_rules or load_effective_rules()).suspicious_imports
        except Exception:
            weights = {}

        for name in matched:
            w = ctk.CTkFrame(card, fg_color="transparent")
            w.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(w, text="✗", font=(UI, 11, "bold"),
                         text_color=RISK_HIGH, width=16).pack(side="left")
            ctk.CTkLabel(w, text=name, font=MONO_SM, text_color=TEXT).pack(side="left", padx=(4, 0))
            ctk.CTkLabel(w, text=f"  [ {weights.get(name, '?')} pts ]",
                         font=(UI, 10), text_color=TEXT_DIM).pack(side="left")
        ctk.CTkFrame(card, fg_color="transparent", height=6).pack()

    def _section_strings(self, parent, r: dict):
        total = r["suspicious_indicators_total"]
        self._sep(parent, f"Suspicious Strings  —  {total} found")

        card = self._mk_card(parent)
        card.pack(fill="x", padx=16, pady=(0, 4))

        for s in r["suspicious_indicators_all"]:
            f = ctk.CTkFrame(card, fg_color="transparent")
            f.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(f, text="•", font=(UI, 12, "bold"),
                         text_color=RISK_MED, width=12).pack(side="left")
            ctk.CTkLabel(f, text=s, font=MONO_SM, text_color=TEXT_MONO,
                         anchor="w").pack(side="left", padx=(4, 0))
        ctk.CTkFrame(card, fg_color="transparent", height=6).pack()

    # ── Action bar ────────────────────────────────────────────────────────────

    def _action_bar(self, parent, r: dict):
        bar = ctk.CTkFrame(parent, fg_color="transparent")
        bar.pack(fill="x", padx=16, pady=(16, 20))
        kw = dict(font=(UI, 11, "bold"), height=34, corner_radius=6)

        if r["risk"]["level"] in ("HIGH", "MEDIUM"):
            ctk.CTkButton(
                bar, text="⬛  Isolate File",
                fg_color=RISK_H_BG, hover_color="#3a0020",
                border_color=RISK_HIGH, border_width=1, text_color=RISK_HIGH,
                command=self._isolate, **kw,
            ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            bar, text="⎘  Copy JSON",
            fg_color=BG3, hover_color=BG_HOVER,
            border_color=BORDER, border_width=1, text_color=TEXT,
            command=self._copy_json, **kw,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            bar, text="💾  Save Report",
            fg_color=BG3, hover_color=BG_HOVER,
            border_color=BORDER, border_width=1, text_color=TEXT,
            command=self._save_report, **kw,
        ).pack(side="left")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _load_rules(self):
        path = filedialog.askopenfilename(
            title="Load rules file",
            filetypes=[("JSON rules", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            from .rules import load_rules_from_path
            self._active_rules = load_rules_from_path(path)
            name = Path(path).name
            self._rules_lbl.configure(text=f"rules: {name}")
            self._set_status(f"Rules loaded: {path}")
        except Exception as exc:
            self._set_status(f"Failed to load rules: {exc}", error=True)

    def _isolate(self):
        if not self._results:
            return
        qdir = simpledialog.askstring(
            "Quarantine Directory",
            "Enter quarantine directory path:",
            initialvalue="quarantine",
            parent=self,
        )
        if not qdir:
            return
        r = self._results
        result = isolate_file(
            file_path=r["file_path"],
            quarantine_dir=qdir,
            sha256_hex=r["file_info"]["sha256"],
            trigger_reason="manual-gui-isolate",
        )
        if result["performed"]:
            append_manifest(os.path.join(qdir, "manifest.jsonl"), r, result, "manual-gui-isolate")
            self._set_status(f"Isolated → {result['path']}")
        else:
            self._set_status(f"Isolation failed: {result['error']}", error=True)

    def _copy_json(self):
        if not self._results:
            return
        self.clipboard_clear()
        self.clipboard_append(json.dumps(self._results, indent=2))
        self._set_status("JSON copied to clipboard.")

    def _save_report(self):
        if not self._results:
            return
        default = f"{Path(self._results['file_path']).stem}_report.json"
        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Text", "*.txt"), ("All", "*.*")],
            initialfile=default,
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._results, f, indent=2)
        self._set_status(f"Report saved → {path}")

    # ── Status ────────────────────────────────────────────────────────────────

    def _set_status(self, msg: str, error: bool = False):
        self._status_lbl.configure(
            text=msg,
            text_color=RED_ACC if error else TEXT_DIM,
        )


# ── Entry ──────────────────────────────────────────────────────────────────────

def run_gui():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    App().mainloop()


if __name__ == "__main__":
    run_gui()
