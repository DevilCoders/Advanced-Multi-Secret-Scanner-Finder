"""Tkinter based GUI for the advanced multi secret scanner."""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .scanner import BatchResult, Finding, SecretScanner


SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff5370",
    "high": "#ffcb6b",
    "medium": "#82aaff",
    "low": "#5fd7a7",
}


@dataclass
class ScanSummary:
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int

    @classmethod
    def from_findings(cls, findings: Iterable[Finding]) -> "ScanSummary":
        severity_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total = 0
        for finding in findings:
            total += 1
            severity_levels[finding.pattern.severity] = (
                severity_levels.get(finding.pattern.severity, 0) + 1
            )
        return cls(
            total_findings=total,
            critical=severity_levels.get("critical", 0),
            high=severity_levels.get("high", 0),
            medium=severity_levels.get("medium", 0),
            low=severity_levels.get("low", 0),
        )


class AsyncScanExecutor:
    """Background asyncio loop orchestrating scan jobs."""

    def __init__(self, scanner: SecretScanner) -> None:
        self.scanner = scanner
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(
            target=self._run_loop,
            name="SecretScannerAsyncLoop",
            daemon=True,
        )
        self.thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit_scan(
        self,
        path: Path,
        *,
        progress_callback=None,
        workers: int | None = None,
    ):
        coroutine = self.scanner.scan_directory_async(
            path,
            progress_callback=progress_callback,
            workers=workers,
        )
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop)

    def submit_batch(
        self,
        paths,
        *,
        per_directory_callback=None,
        batch_progress_callback=None,
        workers: int | None = None,
    ):
        coroutine = self.scanner.scan_batch_async(
            paths,
            per_directory_callback=per_directory_callback,
            batch_progress_callback=batch_progress_callback,
            workers=workers,
        )
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop)

    def submit_callable(self, func):
        async def runner():
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, func)

        return asyncio.run_coroutine_threadsafe(runner(), self.loop)


class SecretScannerGUI:
    """Main GUI application class."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Advanced Multi Secret Scanner")
        self.root.geometry("1280x820")
        self.root.configure(bg="#050505")

        self.scanner = SecretScanner()
        self.executor = AsyncScanExecutor(self.scanner)
        self.current_path: Optional[Path] = None
        self.findings: list[Finding] = []
        self.filtered_findings: list[Finding] = []
        self.current_metadata: dict[str, object] = {"filenames": [], "extensions": [], "extension_counts": {}}
        self.scan_future = None
        self.batch_future = None
        self.batch_jobs: list[Path] = []
        self.batch_results: list[BatchResult] = []

        self.timer_running = False
        self.timer_start = 0.0

        self._configure_style()
        self._build_layout()

    # region UI configuration
    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        primary_bg = "#050505"
        accent = "#0aff9d"
        accent_muted = "#0a7f5f"
        text_color = "#d7ffd9"

        style.configure("TLabel", background=primary_bg, foreground=text_color, font=("Consolas", 12))
        style.configure(
            "Hacker.TButton",
            background=accent_muted,
            foreground=primary_bg,
            font=("Consolas", 11, "bold"),
            padding=6,
        )
        style.map(
            "Hacker.TButton",
            background=[("active", accent), ("disabled", "#1b1b1b")],
            foreground=[("active", primary_bg), ("disabled", "#595959")],
        )
        style.configure("Hacker.TEntry", fieldbackground="#0f1512", foreground=accent, insertcolor=accent)
        style.configure("Hacker.TFrame", background=primary_bg)
        style.configure(
            "Hacker.Treeview",
            background="#0f0f0f",
            fieldbackground="#0f0f0f",
            foreground="#57ffb0",
            rowheight=28,
            bordercolor=accent_muted,
            borderwidth=1,
            relief="flat",
            font=("Consolas", 11),
        )
        style.map(
            "Hacker.Treeview",
            background=[("selected", "#084d3d")],
            foreground=[("selected", accent)],
        )
        style.configure(
            "Hacker.Treeview.Heading",
            background="#072b24",
            foreground=accent,
            font=("Consolas", 11, "bold"),
        )
        style.configure("Hacker.TNotebook", background=primary_bg, borderwidth=0)
        style.configure(
            "Hacker.TNotebook.Tab",
            background="#061010",
            foreground=accent,
            padding=(12, 6),
            font=("Consolas", 11, "bold"),
        )
        style.map(
            "Hacker.TNotebook.Tab",
            background=[("selected", "#0c2c24")],
            foreground=[("selected", accent)],
        )

    def _build_layout(self) -> None:
        header_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        header_frame.pack(fill="x", pady=18, padx=16)

        title_label = ttk.Label(
            header_frame,
            text="// Advanced Multi Secret Scanner \\",
            font=("Consolas", 22, "bold"),
        )
        title_label.grid(row=0, column=0, sticky="w")

        subtitle_label = ttk.Label(
            header_frame,
            text="Harden your codebase. Hunt for secrets like a pro hacker.",
            font=("Consolas", 12),
            foreground="#0aff9d",
        )
        subtitle_label.grid(row=1, column=0, sticky="w", pady=(6, 0))

        header_frame.columnconfigure(1, weight=1)

        self.path_entry = ttk.Entry(header_frame, width=80, style="Hacker.TEntry")
        self.path_entry.grid(row=0, column=1, padx=12, sticky="ew")

        browse_button = ttk.Button(
            header_frame,
            text="Browse",
            style="Hacker.TButton",
            command=self.select_directory,
        )
        browse_button.grid(row=0, column=2, padx=(12, 0))

        scan_button = ttk.Button(
            header_frame,
            text="Initiate Scan",
            style="Hacker.TButton",
            command=self.trigger_scan,
        )
        scan_button.grid(row=1, column=1, sticky="e", pady=(8, 0))

        queue_button = ttk.Button(
            header_frame,
            text="Queue for Batch",
            style="Hacker.TButton",
            command=self.add_current_to_batch,
        )
        queue_button.grid(row=1, column=2, padx=(12, 0), pady=(8, 0))

        export_button = ttk.Button(
            header_frame,
            text="Export Findings",
            style="Hacker.TButton",
            command=self.export_findings,
        )
        export_button.grid(row=0, column=3, padx=(12, 0))

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            self.root,
            style="green.Horizontal.TProgressbar",
            orient="horizontal",
            mode="determinate",
            variable=self.progress_var,
            maximum=100,
        )
        self.progress_bar.pack(fill="x", padx=20)

        style = ttk.Style(self.root)
        style.configure(
            "green.Horizontal.TProgressbar",
            troughcolor="#040404",
            background="#0aff9d",
            bordercolor="#0aff9d",
            lightcolor="#0aff9d",
            darkcolor="#0aff9d",
        )

        status_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        status_frame.pack(fill="x", padx=18, pady=10)

        self.status_label = ttk.Label(
            status_frame,
            text="Awaiting target directory...",
            font=("Consolas", 12),
        )
        self.status_label.pack(side="left")

        self.timer_label = ttk.Label(status_frame, text="00:00", font=("Consolas", 12, "bold"))
        self.timer_label.pack(side="right")

        self.notebook = ttk.Notebook(self.root, style="Hacker.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        self.live_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.batch_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.intel_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.notebook.add(self.live_tab, text="Live Scanner")
        self.notebook.add(self.batch_tab, text="Batch Ops")
        self.notebook.add(self.intel_tab, text="Threat Intel")

        self._build_live_tab()
        self._build_batch_tab()
        self._build_intel_tab()

    def _build_live_tab(self) -> None:
        controls_frame = ttk.Frame(self.live_tab, style="Hacker.TFrame")
        controls_frame.pack(fill="x", pady=(0, 12))

        ttk.Label(controls_frame, text="Search:").pack(side="left", padx=(0, 8))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(controls_frame, textvariable=self.search_var, width=40, style="Hacker.TEntry")
        search_entry.pack(side="left")
        self.search_var.trace_add("write", lambda *_: self._refresh_tree())

        severity_frame = ttk.Frame(controls_frame, style="Hacker.TFrame")
        severity_frame.pack(side="right")
        self.severity_filters: dict[str, tk.BooleanVar] = {}
        for severity in ("critical", "high", "medium", "low"):
            var = tk.BooleanVar(value=True)
            chk = ttk.Checkbutton(
                severity_frame,
                text=severity.upper(),
                variable=var,
                style="TCheckbutton",
                command=self._refresh_tree,
            )
            chk.pack(side="left", padx=4)
            self.severity_filters[severity] = var

        split_pane = ttk.Panedwindow(self.live_tab, orient="horizontal")
        split_pane.pack(fill="both", expand=True)

        tree_container = ttk.Frame(split_pane, style="Hacker.TFrame")
        detail_container = ttk.Frame(split_pane, style="Hacker.TFrame")
        split_pane.add(tree_container, weight=3)
        split_pane.add(detail_container, weight=2)

        columns = ("severity", "pattern", "file", "line", "snippet")
        self.tree = ttk.Treeview(
            tree_container,
            columns=columns,
            show="headings",
            style="Hacker.Treeview",
            selectmode="browse",
        )

        headings = {
            "severity": "Severity",
            "pattern": "Indicator",
            "file": "File",
            "line": "Line",
            "snippet": "Snippet",
        }
        for col, text in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, anchor="w")

        self.tree.column("severity", width=120, anchor="center")
        self.tree.column("pattern", width=240)
        self.tree.column("file", width=440)
        self.tree.column("line", width=80, anchor="center")
        self.tree.column("snippet", width=420)

        for severity, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(severity, foreground=color)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.pack(fill="both", expand=True, side="left")

        y_scroll = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        y_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=y_scroll.set)

        detail_header = ttk.Label(
            detail_container,
            text="Finding Intel",
            font=("Consolas", 14, "bold"),
        )
        detail_header.pack(anchor="w")

        self.detail_text = tk.Text(
            detail_container,
            background="#0f1512",
            foreground="#0aff9d",
            insertbackground="#0aff9d",
            relief="flat",
            height=20,
            font=("Consolas", 11),
            wrap="none",
            state="disabled",
        )
        self.detail_text.pack(fill="both", expand=True, pady=(8, 8))

        self.detail_meta_label = ttk.Label(
            detail_container,
            text="Select a finding to inspect contextual intelligence.",
            font=("Consolas", 11),
            wraplength=360,
            justify="left",
        )
        self.detail_meta_label.pack(anchor="w")

        summary_frame = ttk.Frame(self.live_tab, style="Hacker.TFrame")
        summary_frame.pack(fill="x", pady=(12, 0))

        self.summary_label = ttk.Label(
            summary_frame,
            text="No scans executed yet.",
            font=("Consolas", 12),
        )
        self.summary_label.pack(side="left")

    def _build_batch_tab(self) -> None:
        control_frame = ttk.Frame(self.batch_tab, style="Hacker.TFrame")
        control_frame.pack(fill="x", pady=(0, 12))

        add_button = ttk.Button(
            control_frame,
            text="Add Directory",
            style="Hacker.TButton",
            command=self.add_directory_to_batch,
        )
        add_button.pack(side="left")

        remove_button = ttk.Button(
            control_frame,
            text="Remove Selected",
            style="Hacker.TButton",
            command=self.remove_selected_batch,
        )
        remove_button.pack(side="left", padx=(12, 0))

        clear_button = ttk.Button(
            control_frame,
            text="Clear Queue",
            style="Hacker.TButton",
            command=self.clear_batch_queue,
        )
        clear_button.pack(side="left", padx=(12, 0))

        self.batch_start_button = ttk.Button(
            control_frame,
            text="Run Batch Scan",
            style="Hacker.TButton",
            command=self.start_batch_scan,
        )
        self.batch_start_button.pack(side="right")

        queue_container = ttk.Frame(self.batch_tab, style="Hacker.TFrame")
        queue_container.pack(fill="x", pady=(0, 12))

        ttk.Label(queue_container, text="Queued directories:").pack(anchor="w")
        self.batch_listbox = tk.Listbox(
            queue_container,
            background="#0f1512",
            foreground="#0aff9d",
            selectmode=tk.EXTENDED,
            relief="flat",
            highlightthickness=1,
            highlightbackground="#0aff9d",
            height=6,
            font=("Consolas", 11),
        )
        self.batch_listbox.pack(fill="x", expand=False, pady=(6, 0))

        progress_frame = ttk.Frame(self.batch_tab, style="Hacker.TFrame")
        progress_frame.pack(fill="x", pady=(0, 12))

        self.batch_detail_label = ttk.Label(
            progress_frame,
            text="Batch idle.",
            font=("Consolas", 11),
        )
        self.batch_detail_label.pack(side="left")

        self.batch_progress_var = tk.DoubleVar(value=0.0)
        self.batch_progress_bar = ttk.Progressbar(
            progress_frame,
            orient="horizontal",
            mode="determinate",
            variable=self.batch_progress_var,
            maximum=100,
            style="green.Horizontal.TProgressbar",
        )
        self.batch_progress_bar.pack(side="right", fill="x", expand=True, padx=(12, 0))

        self.batch_status_label = ttk.Label(
            self.batch_tab,
            text="No batch runs yet.",
            font=("Consolas", 11),
        )
        self.batch_status_label.pack(anchor="w")

        results_frame = ttk.Frame(self.batch_tab, style="Hacker.TFrame")
        results_frame.pack(fill="both", expand=True, pady=(12, 0))

        columns = ("target", "critical", "high", "medium", "low", "total", "duration")
        self.batch_tree = ttk.Treeview(
            results_frame,
            columns=columns,
            show="headings",
            style="Hacker.Treeview",
        )
        headings = {
            "target": "Directory",
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "total": "Findings",
            "duration": "Duration",
        }
        for col, text in headings.items():
            self.batch_tree.heading(col, text=text)
            anchor = "e" if col in {"critical", "high", "medium", "low", "total"} else "w"
            width = 180 if col == "target" else 110
            self.batch_tree.column(col, anchor=anchor, width=width)
        self.batch_tree.pack(fill="both", expand=True, side="left")

        scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.batch_tree.yview)
        scroll.pack(side="right", fill="y")
        self.batch_tree.configure(yscrollcommand=scroll.set)

    def _build_intel_tab(self) -> None:
        header_frame = ttk.Frame(self.intel_tab, style="Hacker.TFrame")
        header_frame.pack(fill="x", pady=(0, 16))

        self.risk_score_label = ttk.Label(
            header_frame,
            text="Risk Score: 0",
            font=("Consolas", 16, "bold"),
        )
        self.risk_score_label.pack(side="left")

        severity_frame = ttk.Frame(header_frame, style="Hacker.TFrame")
        severity_frame.pack(side="right")

        self.severity_value_labels: dict[str, ttk.Label] = {}
        for severity in ("critical", "high", "medium", "low"):
            label = ttk.Label(
                severity_frame,
                text=f"{severity.upper()}: 0",
                foreground=SEVERITY_COLORS.get(severity, "#0aff9d"),
                font=("Consolas", 11, "bold"),
            )
            label.pack(side="left", padx=8)
            self.severity_value_labels[severity] = label

        patterns_frame = ttk.Frame(self.intel_tab, style="Hacker.TFrame")
        patterns_frame.pack(fill="x", pady=(0, 12))

        ttk.Label(patterns_frame, text="Top Indicators:").pack(anchor="w")
        self.patterns_tree = ttk.Treeview(
            patterns_frame,
            columns=("pattern", "count"),
            show="headings",
            style="Hacker.Treeview",
            height=6,
        )
        self.patterns_tree.heading("pattern", text="Pattern")
        self.patterns_tree.heading("count", text="Hits")
        self.patterns_tree.column("pattern", width=420, anchor="w")
        self.patterns_tree.column("count", width=120, anchor="center")
        self.patterns_tree.pack(fill="x", pady=(6, 0))

        intel_split = ttk.Frame(self.intel_tab, style="Hacker.TFrame")
        intel_split.pack(fill="both", expand=True, pady=(16, 0))

        suspicious_frame = ttk.Frame(intel_split, style="Hacker.TFrame")
        suspicious_frame.pack(side="left", fill="both", expand=True)

        ttk.Label(suspicious_frame, text="Sensitive Filenames Detected:").pack(anchor="w")
        self.filename_listbox = tk.Listbox(
            suspicious_frame,
            background="#0f1512",
            foreground="#0aff9d",
            height=12,
            selectmode=tk.BROWSE,
            relief="flat",
            font=("Consolas", 11),
        )
        self.filename_listbox.pack(fill="both", expand=True, pady=(6, 0), padx=(0, 12))

        extension_frame = ttk.Frame(intel_split, style="Hacker.TFrame")
        extension_frame.pack(side="left", fill="both", expand=True)

        ttk.Label(extension_frame, text="Sensitive Extension Density:").pack(anchor="w")
        self.extension_listbox = tk.Listbox(
            extension_frame,
            background="#0f1512",
            foreground="#0aff9d",
            height=12,
            selectmode=tk.BROWSE,
            relief="flat",
            font=("Consolas", 11),
        )
        self.extension_listbox.pack(fill="both", expand=True, pady=(6, 0))

        self.metadata_summary_label = ttk.Label(
            self.intel_tab,
            text="No metadata collected yet.",
            font=("Consolas", 11),
            wraplength=900,
        )
        self.metadata_summary_label.pack(anchor="w", pady=(12, 0))

    # endregion

    def select_directory(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, directory)
            self.current_path = Path(directory)
            self.status_label.config(text=f"Target locked: {directory}")

    def trigger_scan(self) -> None:
        if self.scan_future and not self.scan_future.done():
            messagebox.showinfo("Scan in progress", "Please wait for the current scan to complete.")
            return

        path_value = self.path_entry.get().strip()
        if not path_value:
            messagebox.showwarning("Missing target", "Select a directory to scan.")
            return

        path = Path(path_value)
        if not path.exists() or not path.is_dir():
            messagebox.showerror("Invalid directory", "The selected path is not a directory.")
            return

        self.current_path = path
        self.findings.clear()
        self.filtered_findings.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress_var.set(0)
        self.status_label.config(text="Initializing deep scan...")
        self.summary_label.config(text="Scanning in progress...")

        def on_progress(current: int, total: int, file_path: Optional[Path]) -> None:
            self.root.after(0, lambda: self._update_single_progress(current, total, file_path))

        self.scan_future = self.executor.submit_scan(path, progress_callback=on_progress)
        self.timer_running = True
        self.timer_start = time.time()
        self._update_timer()
        self.scan_future.add_done_callback(lambda future: self.root.after(0, lambda: self._handle_scan_result(future, path)))

    def _update_timer(self) -> None:
        if not self.timer_running:
            return
        elapsed = int(time.time() - self.timer_start)
        minutes, seconds = divmod(elapsed, 60)
        self.timer_label.config(text=f"{minutes:02d}:{seconds:02d}")
        self.root.after(1000, self._update_timer)

    def _update_single_progress(self, current: int, total: int, path: Optional[Path]) -> None:
        progress = (current / total) * 100 if total else 0
        self.progress_var.set(progress)
        if path:
            display = self._safe_truncate_path(path)
            self.status_label.config(text=f"Scanning {display}")
        else:
            self.status_label.config(text="Scan complete")

    def _handle_scan_result(self, future, path: Path) -> None:
        self.timer_running = False
        self.timer_label.config(text="00:00")
        try:
            findings = future.result()
        except Exception as exc:  # noqa: BLE001 - surface worker errors
            messagebox.showerror("Scan failed", str(exc))
            self.status_label.config(text="Scan failed.")
            return

        metadata_future = self.executor.submit_callable(lambda: self.scanner.collect_metadata(path))

        def deliver_metadata(meta_future) -> None:
            try:
                metadata = meta_future.result()
            except Exception:  # pragma: no cover - rare filesystem issues
                metadata = {"filenames": [], "extensions": [], "extension_counts": {}}
            self._display_results(findings, metadata)

        metadata_future.add_done_callback(lambda mf: self.root.after(0, lambda: deliver_metadata(mf)))

    def _display_results(self, findings: list[Finding], metadata: dict[str, object]) -> None:
        self.findings = findings
        self.current_metadata = metadata
        self._refresh_tree()
        summary = ScanSummary.from_findings(findings)
        telemetry = self.scanner.compute_telemetry(findings)
        risk_score = telemetry.get("risk_score", 0)
        self.summary_label.config(
            text=(
                f"Findings: {summary.total_findings} | Critical: {summary.critical} | "
                f"High: {summary.high} | Medium: {summary.medium} | Low: {summary.low} | "
                f"Risk Score: {risk_score}"
            )
        )
        if not findings:
            self.status_label.config(text="Scan complete - no indicators found.")
        else:
            self.status_label.config(text="Scan complete - review flagged entries.")
        self._update_intel_panel()

    def _refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().lower()
        allowed = {
            severity for severity, var in self.severity_filters.items() if var.get()
        }
        results: list[Finding] = []
        for finding in self.findings:
            if finding.pattern.severity not in allowed:
                continue
            haystack = " ".join(
                [
                    finding.pattern.name.lower(),
                    finding.pattern.description.lower(),
                    str(finding.file_path).lower(),
                    finding.line.lower(),
                ]
            )
            if query and query not in haystack:
                continue
            results.append(finding)

        self.filtered_findings = results
        tree_map = {}
        for finding in results:
            snippet = finding.line.strip()
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."
            item = self.tree.insert(
                "",
                "end",
                values=(
                    finding.pattern.severity.upper(),
                    finding.pattern.name,
                    str(finding.file_path),
                    finding.line_number,
                    snippet,
                ),
                tags=(finding.pattern.severity,),
            )
            tree_map[item] = finding
        self._tree_finding_map = tree_map

    def _on_tree_select(self, _: tk.Event) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        item = selection[0]
        finding = self._tree_finding_map.get(item)
        if not finding:
            return
        self._render_context_for_finding(finding)

    def _render_context_for_finding(self, finding: Finding, radius: int = 3) -> None:
        try:
            with finding.file_path.open("r", encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
        except OSError:
            context = "Unable to read file for preview."
        else:
            start = max(finding.line_number - radius - 1, 0)
            end = min(len(lines), finding.line_number + radius)
            context_lines = []
            for idx in range(start, end):
                prefix = "➤ " if (idx + 1) == finding.line_number else "   "
                context_lines.append(f"{prefix}{idx + 1:>4}: {lines[idx].rstrip()}")
            context = "\n".join(context_lines) or "No additional context available."

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", context)
        self.detail_text.configure(state="disabled")
        self.detail_meta_label.config(
            text=(
                f"{finding.pattern.name} · {finding.pattern.severity.upper()}\n"
                f"{finding.file_path} @ line {finding.line_number}"
            )
        )

    def _update_intel_panel(self) -> None:
        telemetry = self.scanner.compute_telemetry(self.findings)
        risk_score = telemetry.get("risk_score", 0)
        self.risk_score_label.config(text=f"Risk Score: {risk_score}")

        severity_counts = telemetry.get("severity", {})
        for severity, label in self.severity_value_labels.items():
            label.config(text=f"{severity.upper()}: {severity_counts.get(severity, 0)}")

        self.patterns_tree.delete(*self.patterns_tree.get_children())
        for pattern, count in telemetry.get("top_patterns", []):
            self.patterns_tree.insert("", "end", values=(pattern, count))

        filenames = self.current_metadata.get("filenames", [])
        extensions = self.current_metadata.get("extension_counts", {})

        self.filename_listbox.delete(0, tk.END)
        for name in filenames:
            self.filename_listbox.insert(tk.END, name)

        self.extension_listbox.delete(0, tk.END)
        for suffix, count in extensions.items():
            self.extension_listbox.insert(tk.END, f"{suffix}: {count} file(s)")

        meta_text_parts = []
        if filenames:
            meta_text_parts.append(f"Sensitive filenames: {len(filenames)}")
        if extensions:
            meta_text_parts.append(
                "Top risky extensions: "
                + ", ".join(f"{suffix}({count})" for suffix, count in extensions.items())
            )
        if not meta_text_parts:
            meta_text_parts.append("No additional metadata heuristics flagged.")
        self.metadata_summary_label.config(text=" | ".join(meta_text_parts))

    def add_directory_to_batch(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            path = Path(directory)
            if path not in self.batch_jobs:
                self.batch_jobs.append(path)
                self.batch_listbox.insert(tk.END, str(path))

    def add_current_to_batch(self) -> None:
        value = self.path_entry.get().strip()
        if value:
            path = Path(value)
            if path not in self.batch_jobs and path.exists():
                self.batch_jobs.append(path)
                self.batch_listbox.insert(tk.END, str(path))
                self.batch_status_label.config(text=f"Queued {path}")

    def remove_selected_batch(self) -> None:
        selection = list(self.batch_listbox.curselection())
        if not selection:
            return
        for index in reversed(selection):
            self.batch_listbox.delete(index)
            del self.batch_jobs[index]

    def clear_batch_queue(self) -> None:
        self.batch_jobs.clear()
        self.batch_listbox.delete(0, tk.END)
        self.batch_status_label.config(text="Queue cleared.")

    def start_batch_scan(self) -> None:
        if self.batch_future and not self.batch_future.done():
            messagebox.showinfo("Batch running", "A batch scan is already executing.")
            return
        if not self.batch_jobs:
            messagebox.showwarning("Empty queue", "Add directories to the batch queue first.")
            return

        self.batch_status_label.config(text="Batch scan initialized.")
        self.batch_progress_var.set(0)
        self.batch_detail_label.config(text="Awaiting worker feedback...")

        def per_directory_progress(root_path: Path, current: int, total: int, file_path: Optional[Path]) -> None:
            self.root.after(0, lambda: self._batch_file_progress(root_path, current, total, file_path))

        def overall_progress(completed: int, total: int, root_path: Path) -> None:
            self.root.after(0, lambda: self._batch_overall_progress(completed, total, root_path))

        self.batch_future = self.executor.submit_batch(
            self.batch_jobs,
            per_directory_callback=per_directory_progress,
            batch_progress_callback=overall_progress,
        )
        self.batch_future.add_done_callback(lambda future: self.root.after(0, lambda: self._on_batch_complete(future)))
        self.timer_running = True
        self.timer_start = time.time()
        self._update_timer()
        self._set_batch_controls_state("disabled")

    def _batch_file_progress(
        self,
        root_path: Path,
        current: int,
        total: int,
        file_path: Optional[Path],
    ) -> None:
        percent = (current / total) * 100 if total else 0
        if file_path:
            display = self._safe_truncate_path(file_path)
            self.batch_detail_label.config(
                text=f"{root_path.name}: {percent:5.1f}% · {display}"
            )
        else:
            self.batch_detail_label.config(text=f"{root_path.name}: complete")

    def _batch_overall_progress(self, completed: int, total: int, root_path: Path) -> None:
        percent = (completed / total) * 100 if total else 0
        self.batch_progress_var.set(percent)
        self.batch_status_label.config(
            text=f"Batch progress: {completed}/{total} directories processed (latest: {root_path})"
        )

    def _on_batch_complete(self, future) -> None:
        self.timer_running = False
        self.timer_label.config(text="00:00")
        self._set_batch_controls_state("normal")
        try:
            results = future.result()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Batch failed", str(exc))
            self.batch_status_label.config(text="Batch scan failed.")
            return

        self.batch_results = results
        self._populate_batch_results(results)
        self.batch_status_label.config(
            text=f"Batch complete: {len(results)} directories scanned."
        )
        if results:
            self.status_label.config(text="Batch scan finished - review aggregated intel.")
        else:
            self.status_label.config(text="Batch scan finished - no directories processed.")

    def _populate_batch_results(self, results: list[BatchResult]) -> None:
        self.batch_tree.delete(*self.batch_tree.get_children())
        for result in results:
            breakdown = result.severity_breakdown()
            total_findings = len(result.findings)
            duration = f"{result.duration_s:.1f}s"
            self.batch_tree.insert(
                "",
                "end",
                values=(
                    str(result.root),
                    breakdown.get("critical", 0),
                    breakdown.get("high", 0),
                    breakdown.get("medium", 0),
                    breakdown.get("low", 0),
                    total_findings,
                    duration,
                ),
            )

    def _set_batch_controls_state(self, state: str) -> None:
        for widget in (self.batch_start_button,):
            widget.configure(state=state)

    def export_findings(self) -> None:
        if not self.findings:
            messagebox.showinfo("No findings", "Nothing to export yet. Run a scan first.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export findings",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not file_path:
            return

        try:
            SecretScanner.export_findings(self.findings, Path(file_path))
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Export complete", f"Findings exported to {file_path}")

    @staticmethod
    def _safe_truncate_path(path: Path, limit: int = 80) -> str:
        value = str(path)
        if len(value) <= limit:
            return value
        return "…" + value[-limit:]


def launch() -> None:
    root = tk.Tk()
    SecretScannerGUI(root)
    root.mainloop()


__all__ = ["SecretScannerGUI", "launch"]
