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

from .scanner import BatchScanResult, Finding, ScanStats, SecretScanner


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


class SecretScannerGUI:
    """Main GUI application class."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Advanced Multi Secret Scanner")
        self.root.geometry("1180x780")
        self.root.minsize(1120, 720)
        self.root.configure(bg="#050505")

        self.scanner = SecretScanner()
        self.scan_thread: Optional[threading.Thread] = None
        self.batch_thread: Optional[threading.Thread] = None
        self.cancel_event = threading.Event()
        self.batch_cancel_event = threading.Event()
        self.current_path: Optional[Path] = None
        self.findings: list[Finding] = []
        self.filtered_findings: list[Finding] = []
        self.metadata: dict[str, list[str]] = {
            "filenames": [],
            "extensions": [],
            "directories": [],
        }
        self.last_stats: Optional[ScanStats] = None
        self.batch_jobs: list[Path] = []
        self.batch_status: dict[str, dict[str, str]] = {}
        self.batch_results: list[BatchScanResult] = []

        # UI control variables
        self.include_hidden_var = tk.BooleanVar(value=self.scanner.include_hidden)
        self.entropy_var = tk.BooleanVar(value=self.scanner.enable_entropy_checks)
        if self.scanner.max_file_size is None:
            initial_max_mb = 0
        else:
            initial_max_mb = max(1, int(self.scanner.max_file_size / (1024 * 1024)))
        self.max_file_size_var = tk.IntVar(value=initial_max_mb)
        self.thread_var = tk.IntVar(value=self.scanner.max_workers)
        self.extensions_var = tk.StringVar(
            value=", ".join(self.scanner.extensions or [])
        )
        self.severity_filter = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar()
        self.batch_concurrency_var = tk.IntVar(value=max(1, self.scanner.max_workers // 2))

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
        style.configure("Hacker.TLabelframe", background=primary_bg, foreground=accent, font=("Consolas", 11, "bold"))
        style.configure("Hacker.TLabelframe.Label", background=primary_bg, foreground=accent, font=("Consolas", 11, "bold"))
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
        style.configure(
            "Hacker.TNotebook",
            background=primary_bg,
            borderwidth=0,
            padding=2,
        )
        style.configure(
            "Hacker.TNotebook.Tab",
            background="#0f0f0f",
            foreground=accent,
            font=("Consolas", 11, "bold"),
            padding=(12, 6),
        )
        style.map(
            "Hacker.TNotebook.Tab",
            background=[("selected", "#0a3629")],
            foreground=[("selected", accent)],
        )

    def _build_layout(self) -> None:
        self.header_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        self.header_frame.pack(fill="x", pady=18, padx=16)

        title_label = ttk.Label(
            self.header_frame,
            text='// Advanced Multi Secret Scanner \\',
            font=("Consolas", 22, "bold"),
        )
        title_label.grid(row=0, column=0, sticky="w")

        subtitle_label = ttk.Label(
            self.header_frame,
            text="Harden your codebase. Hunt for secrets like a pro hacker.",
            font=("Consolas", 12),
            foreground="#0aff9d",
        )
        subtitle_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        self.header_frame.columnconfigure(1, weight=1)

        self.path_entry = ttk.Entry(self.header_frame, width=70, style="Hacker.TEntry")
        self.path_entry.grid(row=0, column=1, padx=12, sticky="ew")

        browse_button = ttk.Button(
            self.header_frame,
            text="Browse",
            style="Hacker.TButton",
            command=self.select_directory,
        )
        browse_button.grid(row=0, column=2, padx=(12, 0))

        add_batch_button = ttk.Button(
            self.header_frame,
            text="Queue Batch",
            style="Hacker.TButton",
            command=self.add_current_path_to_batch,
        )
        add_batch_button.grid(row=0, column=3, padx=(12, 0))

        scan_button = ttk.Button(
            self.header_frame,
            text="Initiate Scan",
            style="Hacker.TButton",
            command=self.trigger_scan,
        )
        scan_button.grid(row=1, column=1, sticky="e", pady=(8, 0))

        self.stop_button = ttk.Button(
            self.header_frame,
            text="Abort Scan",
            style="Hacker.TButton",
            command=self.cancel_scan,
        )
        self.stop_button.grid(row=1, column=2, padx=(12, 0), pady=(8, 0))
        self.stop_button.state(["disabled"])

        export_button = ttk.Button(
            self.header_frame,
            text="Export Findings",
            style="Hacker.TButton",
            command=self.export_findings,
        )
        export_button.grid(row=1, column=3, padx=(12, 0), pady=(8, 0))

        self._build_options_panel()

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            self.root,
            style="green.Horizontal.TProgressbar",
            orient="horizontal",
            mode="determinate",
            variable=self.progress_var,
            maximum=100,
        )
        self.progress_bar.pack(fill="x", padx=20, pady=(6, 0))

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

        self.stats_label = ttk.Label(
            self.root,
            text="Files scanned: 0 | Skipped: 0 | Duration: 0.0s",
            font=("Consolas", 11),
        )
        self.stats_label.pack(fill="x", padx=18)

        self.notebook = ttk.Notebook(self.root, style="Hacker.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(6, 18))

        self._build_results_tab()
        self._build_metadata_tab()
        self._build_batch_tab()

        summary_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        summary_frame.pack(fill="x", padx=18, pady=(0, 18))

        self.summary_label = ttk.Label(
            summary_frame,
            text="No scans executed yet.",
            font=("Consolas", 12),
        )
        self.summary_label.pack(side="left")

    def _build_options_panel(self) -> None:
        options_frame = ttk.Labelframe(
            self.root,
            text="Scan Options",
            style="Hacker.TLabelframe",
            padding=12,
        )
        options_frame.pack(fill="x", padx=18, pady=(0, 8))

        include_hidden_check = ttk.Checkbutton(
            options_frame,
            text="Include hidden",
            style="Hacker.TButton",
            variable=self.include_hidden_var,
            command=self._apply_scanner_options,
        )
        include_hidden_check.grid(row=0, column=0, padx=(0, 12), sticky="w")

        entropy_check = ttk.Checkbutton(
            options_frame,
            text="Entropy heuristics",
            style="Hacker.TButton",
            variable=self.entropy_var,
            command=self._apply_scanner_options,
        )
        entropy_check.grid(row=0, column=1, padx=(0, 12), sticky="w")

        ttk.Label(options_frame, text="Max file size (MB, 0 = ∞):").grid(
            row=0, column=2, padx=(12, 4), sticky="w"
        )
        size_spin = ttk.Spinbox(
            options_frame,
            from_=0,
            to=256,
            textvariable=self.max_file_size_var,
            width=6,
            command=self._apply_scanner_options,
        )
        size_spin.grid(row=0, column=3, sticky="w")

        ttk.Label(options_frame, text="Threads:").grid(row=0, column=4, padx=(12, 4), sticky="w")
        thread_spin = ttk.Spinbox(
            options_frame,
            from_=1,
            to=64,
            textvariable=self.thread_var,
            width=6,
            command=self._apply_scanner_options,
        )
        thread_spin.grid(row=0, column=5, sticky="w")

        ttk.Label(options_frame, text="Extensions (comma separated):").grid(
            row=1, column=0, padx=(0, 12), pady=(8, 0), sticky="w"
        )
        extensions_entry = ttk.Entry(
            options_frame,
            textvariable=self.extensions_var,
            style="Hacker.TEntry",
            width=70,
        )
        extensions_entry.grid(row=1, column=1, columnspan=5, sticky="ew", pady=(8, 0))
        extensions_entry.bind("<FocusOut>", lambda _event: self._apply_scanner_options())
        options_frame.columnconfigure(5, weight=1)

    def _build_results_tab(self) -> None:
        results_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.notebook.add(results_tab, text="Scan Results")

        controls = ttk.Frame(results_tab, style="Hacker.TFrame")
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(controls, text="Severity filter:").pack(side="left")
        self.severity_combo = ttk.Combobox(
            controls,
            values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            state="readonly",
            textvariable=self.severity_filter,
            width=12,
        )
        self.severity_combo.pack(side="left", padx=(6, 18))
        self.severity_combo.bind("<<ComboboxSelected>>", lambda _event: self._apply_filters())

        ttk.Label(controls, text="Search:").pack(side="left")
        search_entry = ttk.Entry(controls, textvariable=self.search_var, style="Hacker.TEntry", width=40)
        search_entry.pack(side="left", padx=(6, 6))
        self.search_var.trace_add("write", lambda *_args: self._apply_filters())

        clear_search = ttk.Button(
            controls,
            text="Clear",
            style="Hacker.TButton",
            command=lambda: self.search_var.set(""),
        )
        clear_search.pack(side="left")

        results_pane = ttk.Panedwindow(results_tab, orient="vertical")
        results_pane.pack(fill="both", expand=True)

        tree_frame = ttk.Frame(results_pane, style="Hacker.TFrame")
        detail_frame = ttk.Frame(results_pane, style="Hacker.TFrame")
        results_pane.add(tree_frame, weight=3)
        results_pane.add(detail_frame, weight=2)

        columns = ("severity", "pattern", "file", "line", "snippet")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            style="Hacker.Treeview",
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

        self.tree.column("severity", width=120)
        self.tree.column("pattern", width=240)
        self.tree.column("file", width=480)
        self.tree.column("line", width=90, anchor="center")
        self.tree.column("snippet", width=420)
        self.tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self._on_result_select())

        self.tree.tag_configure("CRITICAL", foreground="#ff5a5a")
        self.tree.tag_configure("HIGH", foreground="#ffae4d")
        self.tree.tag_configure("MEDIUM", foreground="#0aff9d")
        self.tree.tag_configure("LOW", foreground="#57ffb0")

        detail_header = ttk.Frame(detail_frame, style="Hacker.TFrame")
        detail_header.pack(fill="x")
        ttk.Label(detail_header, text="Context preview:", font=("Consolas", 12, "bold"), foreground="#0aff9d").pack(side="left")
        copy_button = ttk.Button(
            detail_header,
            text="Copy context",
            style="Hacker.TButton",
            command=self._copy_selected_context,
        )
        copy_button.pack(side="right")

        self.detail_text = tk.Text(
            detail_frame,
            background="#020302",
            foreground="#57ffb0",
            insertbackground="#0aff9d",
            font=("Consolas", 11),
            height=12,
            wrap="word",
        )
        self.detail_text.pack(fill="both", expand=True, padx=(0, 2), pady=(6, 0))
        self.detail_text.configure(state="disabled")
        self._clear_detail_panel()

    def _build_metadata_tab(self) -> None:
        metadata_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.notebook.add(metadata_tab, text="Intelligence")

        intro = ttk.Label(
            metadata_tab,
            text="Aggregated intelligence across files, extensions, and directories.",
        )
        intro.pack(anchor="w", pady=(0, 8))

        columns = ("category", "location")
        self.metadata_tree = ttk.Treeview(
            metadata_tab,
            columns=columns,
            show="headings",
            style="Hacker.Treeview",
            height=12,
        )
        self.metadata_tree.heading("category", text="Category")
        self.metadata_tree.heading("location", text="Location")
        self.metadata_tree.column("category", width=180)
        self.metadata_tree.column("location", width=760)
        self.metadata_tree.pack(fill="both", expand=True, side="left")

        metadata_scroll = ttk.Scrollbar(metadata_tab, orient="vertical", command=self.metadata_tree.yview)
        metadata_scroll.pack(side="right", fill="y")
        self.metadata_tree.configure(yscrollcommand=metadata_scroll.set)

        metadata_actions = ttk.Frame(metadata_tab, style="Hacker.TFrame")
        metadata_actions.pack(fill="x", pady=(8, 0))

        self.metadata_label = ttk.Label(metadata_actions, text="No metadata available yet.")
        self.metadata_label.pack(side="left")

        export_meta_button = ttk.Button(
            metadata_actions,
            text="Export intelligence",
            style="Hacker.TButton",
            command=self.export_metadata,
        )
        export_meta_button.pack(side="right")

    def _build_batch_tab(self) -> None:
        batch_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.notebook.add(batch_tab, text="Batch Ops")

        controls = ttk.Frame(batch_tab, style="Hacker.TFrame")
        controls.pack(fill="x", pady=(0, 8))

        add_button = ttk.Button(
            controls,
            text="Add directory...",
            style="Hacker.TButton",
            command=self._prompt_and_add_batch,
        )
        add_button.pack(side="left")

        remove_button = ttk.Button(
            controls,
            text="Remove selected",
            style="Hacker.TButton",
            command=self.remove_selected_batch,
        )
        remove_button.pack(side="left", padx=(12, 0))

        clear_button = ttk.Button(
            controls,
            text="Clear queue",
            style="Hacker.TButton",
            command=self.clear_batch_queue,
        )
        clear_button.pack(side="left", padx=(12, 0))

        ttk.Label(controls, text="Parallel jobs:").pack(side="left", padx=(18, 6))
        self.batch_concurrency_spin = ttk.Spinbox(
            controls,
            from_=1,
            to=32,
            textvariable=self.batch_concurrency_var,
            width=6,
        )
        self.batch_concurrency_spin.pack(side="left")

        self.run_batch_button = ttk.Button(
            controls,
            text="Run batch",
            style="Hacker.TButton",
            command=self.run_batch_jobs,
        )
        self.run_batch_button.pack(side="left", padx=(18, 0))

        self.stop_batch_button = ttk.Button(
            controls,
            text="Abort batch",
            style="Hacker.TButton",
            command=self.stop_batch_jobs,
        )
        self.stop_batch_button.pack(side="left", padx=(12, 0))
        self.stop_batch_button.state(["disabled"])

        columns = ("path", "status", "findings", "duration")
        self.batch_tree = ttk.Treeview(
            batch_tab,
            columns=columns,
            show="headings",
            style="Hacker.Treeview",
            height=12,
        )
        self.batch_tree.heading("path", text="Directory")
        self.batch_tree.heading("status", text="Status")
        self.batch_tree.heading("findings", text="Findings")
        self.batch_tree.heading("duration", text="Duration")
        self.batch_tree.column("path", width=520)
        self.batch_tree.column("status", width=180)
        self.batch_tree.column("findings", width=120)
        self.batch_tree.column("duration", width=120)
        self.batch_tree.pack(fill="both", expand=True, side="left")

        batch_scroll = ttk.Scrollbar(batch_tab, orient="vertical", command=self.batch_tree.yview)
        batch_scroll.pack(side="right", fill="y")
        self.batch_tree.configure(yscrollcommand=batch_scroll.set)

        self.batch_status_label = ttk.Label(
            batch_tab,
            text="Batch queue idle.",
            font=("Consolas", 11),
        )
        self.batch_status_label.pack(fill="x", pady=(8, 0))

    # endregion

    def select_directory(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, directory)
            self.current_path = Path(directory)
            self.status_label.config(text=f"Target locked: {directory}")

    def _apply_scanner_options(self) -> None:
        raw_size = int(self.max_file_size_var.get())
        max_size = 0 if raw_size <= 0 else raw_size * 1024 * 1024
        threads = max(1, int(self.thread_var.get()))
        raw_extensions = [ext.strip() for ext in self.extensions_var.get().split(",")]
        extensions = [ext if ext.startswith(".") else f".{ext}" for ext in raw_extensions if ext]
        self.scanner.update_settings(
            include_hidden=self.include_hidden_var.get(),
            max_file_size=max_size,
            extensions=extensions,
            max_workers=threads,
            enable_entropy_checks=self.entropy_var.get(),
        )

    def trigger_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
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

        self._apply_scanner_options()
        self.current_path = path
        self.findings.clear()
        self.filtered_findings.clear()
        self.metadata = {"filenames": [], "extensions": [], "directories": []}
        self.last_stats = None
        self.tree.delete(*self.tree.get_children())
        self.metadata_tree.delete(*self.metadata_tree.get_children())
        self._clear_detail_panel()
        self.progress_var.set(0)
        self.summary_label.config(text="Executing deep scan...")
        self.stats_label.config(text="Files scanned: 0 | Skipped: 0 | Duration: 0.0s")
        self.status_label.config(text="Initializing deep scan...")
        self.stop_button.state(["!disabled"])
        self.cancel_event.clear()

        self.scan_thread = threading.Thread(target=self._run_scan, daemon=True)
        self.scan_thread.start()
        self._start_timer()

    def cancel_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.cancel_event.set()
            self.status_label.config(text="Cancellation requested...")

    def _start_timer(self) -> None:
        start_time = time.time()

        def update_timer() -> None:
            if self.scan_thread and self.scan_thread.is_alive():
                elapsed = int(time.time() - start_time)
                minutes, seconds = divmod(elapsed, 60)
                self.timer_label.config(text=f"{minutes:02d}:{seconds:02d}")
                self.root.after(1000, update_timer)
            else:
                elapsed = int(time.time() - start_time)
                minutes, seconds = divmod(elapsed, 60)
                self.timer_label.config(text=f"{minutes:02d}:{seconds:02d}")

        update_timer()

    def _run_scan(self) -> None:
        assert self.current_path is not None

        def on_progress(current: int, total: int, path: Optional[Path]) -> None:
            def update() -> None:
                progress = (current / total) * 100 if total else 0
                self.progress_var.set(progress)
                if path:
                    display = str(path)[-80:]
                    self.status_label.config(text=f"Scanning {display}")
                else:
                    if self.scanner.last_scan_cancelled or self.cancel_event.is_set():
                        self.status_label.config(text="Scan cancelled")
                    else:
                        self.status_label.config(text="Scan complete")

            self.root.after(0, update)

        try:
            findings = asyncio.run(
                self.scanner.async_scan_directory(
                    self.current_path,
                    progress_callback=on_progress,
                    cancel_event=self.cancel_event,
                )
            )
            metadata = SecretScanner.collect_metadata(self.current_path)
            stats = self.scanner.last_stats
        except Exception as exc:  # noqa: BLE001 - surfacing to UI
            self.root.after(0, lambda: messagebox.showerror("Scan failed", str(exc)))
            self.root.after(0, lambda: self.stop_button.state(["disabled"]))
            self.cancel_event.clear()
            return

        self.findings = findings
        self.metadata = metadata
        self.last_stats = stats
        cancelled = self.scanner.last_scan_cancelled or self.cancel_event.is_set()

        def finalize() -> None:
            self._display_results(findings, metadata, stats, cancelled)
            self.stop_button.state(["disabled"])
            self.cancel_event.clear()

        self.root.after(0, finalize)

    def _display_results(
        self,
        findings: list[Finding],
        metadata: dict[str, list[str]],
        stats: Optional[ScanStats],
        cancelled: bool,
    ) -> None:
        self._apply_filters()
        summary = ScanSummary.from_findings(findings)

        meta_parts: list[str] = []
        if metadata.get("filenames"):
            meta_parts.append(f"Sensitive names: {len(metadata['filenames'])}")
        if metadata.get("extensions"):
            meta_parts.append(f"Sensitive extensions: {len(metadata['extensions'])}")
        if metadata.get("directories"):
            meta_parts.append(f"Sensitive directories: {len(metadata['directories'])}")

        summary_text = (
            f"Findings: {summary.total_findings} | Critical: {summary.critical} | "
            f"High: {summary.high} | Medium: {summary.medium} | Low: {summary.low}"
        )
        if meta_parts:
            summary_text += " | " + " | ".join(meta_parts)
        if cancelled:
            summary_text += " | Scan cancelled"
        self.summary_label.config(text=summary_text)

        if stats:
            self.stats_label.config(
                text=(
                    f"Files scanned: {stats.scanned_files}/{stats.total_files} | "
                    f"Skipped: {stats.skipped_files} | Duration: {stats.duration:.2f}s"
                )
            )
        else:
            self.stats_label.config(text="Files scanned: 0 | Skipped: 0 | Duration: 0.0s")

        if not findings:
            self.status_label.config(
                text="Scan complete - no indicators found." if not cancelled else "Scan cancelled."
            )
        else:
            self.status_label.config(
                text="Scan complete - review flagged entries." if not cancelled else "Scan cancelled - partial results shown."
            )

        self._update_metadata_tab(metadata)

    def _apply_filters(self) -> None:
        severity = self.severity_filter.get().lower()
        query = self.search_var.get().strip().lower()

        filtered: list[Finding] = []
        for finding in self.findings:
            if severity != "all" and finding.pattern.severity.lower() != severity:
                continue
            haystack = f"{finding.pattern.name} {finding.line} {finding.file_path}".lower()
            if query and query not in haystack:
                continue
            filtered.append(finding)

        self._populate_tree(filtered)

    def _populate_tree(self, findings: list[Finding]) -> None:
        self.tree.delete(*self.tree.get_children())
        self.filtered_findings = findings
        for index, finding in enumerate(findings):
            snippet = finding.line.strip() or finding.context.strip()
            if len(snippet) > 140:
                snippet = snippet[:137] + "..."
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    finding.pattern.severity.upper(),
                    finding.pattern.name,
                    str(finding.file_path),
                    finding.line_number,
                    snippet,
                ),
                tags=(finding.pattern.severity.upper(),),
            )
        if not findings:
            self._clear_detail_panel()

    def _on_result_select(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        try:
            index = int(selection[0])
        except ValueError:
            return
        if index >= len(self.filtered_findings):
            return
        finding = self.filtered_findings[index]
        self._update_detail_panel(finding)

    def _update_detail_panel(self, finding: Finding) -> None:
        context_lines = finding.context or finding.line
        text = (
            f"Severity: {finding.pattern.severity.upper()}\n"
            f"Indicator: {finding.pattern.name}\n"
            f"File: {finding.file_path}\n"
            f"Line: {finding.line_number}\n"
            f"Description: {finding.pattern.description}\n\n"
            f"{context_lines.strip()}"
        )
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def _clear_detail_panel(self) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(
            "1.0",
            "Context preview will appear here when you select a finding."
            " Use the filters above to focus on critical signals.",
        )
        self.detail_text.configure(state="disabled")

    def _copy_selected_context(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select a finding to copy its context.")
            return
        index = int(selection[0])
        if index >= len(self.filtered_findings):
            return
        finding = self.filtered_findings[index]
        self.root.clipboard_clear()
        self.root.clipboard_append(finding.context or finding.line)
        messagebox.showinfo("Copied", "Context copied to clipboard.")

    def _update_metadata_tab(self, metadata: dict[str, list[str]]) -> None:
        self.metadata_tree.delete(*self.metadata_tree.get_children())
        rows = []
        for file in metadata.get("filenames", []):
            rows.append(("Sensitive filename", file))
        for file in metadata.get("extensions", []):
            rows.append(("Sensitive extension", file))
        for directory in metadata.get("directories", []):
            rows.append(("Sensitive directory", directory))

        if not rows:
            self.metadata_tree.insert("", "end", values=("None", "No sensitive intelligence captured."))
            self.metadata_label.config(text="No metadata available yet.")
        else:
            for category, location in rows:
                self.metadata_tree.insert("", "end", values=(category, location))
            self.metadata_label.config(text=f"Metadata entries: {len(rows)}")

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

    def export_metadata(self) -> None:
        if not any(self.metadata.values()):
            messagebox.showinfo("No metadata", "Metadata export requires a completed scan.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Export intelligence",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")],
        )
        if not file_path:
            return
        lines = ["== Sensitive intelligence ==\n"]
        for key, values in self.metadata.items():
            lines.append(f"[{key}]\n")
            if values:
                lines.extend(f" - {value}\n" for value in values)
            else:
                lines.append(" - none\n")
            lines.append("\n")
        Path(file_path).write_text("".join(lines), encoding="utf-8")
        messagebox.showinfo("Export complete", f"Metadata exported to {file_path}")

    # Batch management -------------------------------------------------
    def add_current_path_to_batch(self) -> None:
        path_value = self.path_entry.get().strip()
        if not path_value:
            messagebox.showinfo("No path", "Provide a directory in the target field first.")
            return
        path = Path(path_value)
        if not path.exists() or not path.is_dir():
            messagebox.showerror("Invalid directory", "The provided path is not a directory.")
            return
        if path in self.batch_jobs:
            messagebox.showinfo("Already queued", "This directory is already in the batch queue.")
            return
        self.batch_jobs.append(path)
        self.batch_status[str(path)] = {"status": "Queued", "findings": "-", "duration": "-"}
        self._refresh_batch_tree()
        self.batch_status_label.config(text=f"Queued {len(self.batch_jobs)} directories.")

    def _prompt_and_add_batch(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, directory)
            self.add_current_path_to_batch()

    def _refresh_batch_tree(self) -> None:
        existing = set(self.batch_tree.get_children())
        for path in self.batch_jobs:
            key = str(path)
            info = self.batch_status.get(key, {"status": "Queued", "findings": "-", "duration": "-"})
            values = (key, info.get("status", "Queued"), info.get("findings", "-"), info.get("duration", "-"))
            if key in existing:
                self.batch_tree.item(key, values=values)
                existing.remove(key)
            else:
                self.batch_tree.insert("", "end", iid=key, values=values)
        for extra in existing:
            self.batch_tree.delete(extra)

    def remove_selected_batch(self) -> None:
        selection = self.batch_tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select entries to remove from the batch queue.")
            return
        for item in selection:
            path = Path(item)
            if path in self.batch_jobs:
                self.batch_jobs.remove(path)
            self.batch_status.pop(item, None)
        self._refresh_batch_tree()
        self.batch_status_label.config(text=f"Queued {len(self.batch_jobs)} directories.")

    def clear_batch_queue(self) -> None:
        self.batch_jobs.clear()
        self.batch_status.clear()
        self.batch_tree.delete(*self.batch_tree.get_children())
        self.batch_status_label.config(text="Batch queue cleared.")

    def run_batch_jobs(self) -> None:
        if self.batch_thread and self.batch_thread.is_alive():
            messagebox.showinfo("Batch running", "A batch operation is already in progress.")
            return
        if not self.batch_jobs:
            messagebox.showwarning("Empty queue", "Queue directories before launching a batch scan.")
            return

        self._apply_scanner_options()
        concurrency = max(1, int(self.batch_concurrency_var.get()))
        self.batch_cancel_event.clear()
        self.stop_batch_button.state(["!disabled"])
        self.run_batch_button.state(["disabled"])
        self.batch_status_label.config(text="Batch scan in progress...")

        for path in self.batch_jobs:
            self._update_batch_status(path, status="Pending", findings="-", duration="-")

        def worker() -> None:
            try:
                results = asyncio.run(
                    self.scanner.async_batch_scan(
                        self.batch_jobs,
                        parallel_jobs=concurrency,
                        progress_callback=self._batch_progress_callback,
                        cancel_event=self.batch_cancel_event,
                    )
                )
                cancelled = self.batch_cancel_event.is_set()
                self.root.after(0, lambda: self._on_batch_complete(results, cancelled))
            except Exception as exc:  # noqa: BLE001 - bubble to UI
                self.root.after(0, lambda: messagebox.showerror("Batch failed", str(exc)))
                self.root.after(0, lambda: self._on_batch_complete([], False))
            finally:
                self.batch_cancel_event.clear()

        self.batch_thread = threading.Thread(target=worker, daemon=True)
        self.batch_thread.start()

    def stop_batch_jobs(self) -> None:
        if self.batch_thread and self.batch_thread.is_alive():
            self.batch_cancel_event.set()
            self.batch_status_label.config(text="Batch cancellation requested...")

    def _batch_progress_callback(self, path: Path, current: int, total: int) -> None:
        def update() -> None:
            percent = int((current / total) * 100) if total else 0
            status = f"Running {percent}%"
            self._update_batch_status(path, status=status)

        self.root.after(0, update)

    def _update_batch_status(
        self,
        path: Path,
        *,
        status: Optional[str] = None,
        findings: Optional[str] = None,
        duration: Optional[str] = None,
    ) -> None:
        key = str(path)
        info = self.batch_status.setdefault(key, {"status": "Queued", "findings": "-", "duration": "-"})
        if status is not None:
            info["status"] = status
        if findings is not None:
            info["findings"] = findings
        if duration is not None:
            info["duration"] = duration
        self._refresh_batch_tree()

    def _on_batch_complete(self, results: list[BatchScanResult], cancelled: bool) -> None:
        self.batch_results = results
        for result in results:
            summary = ScanSummary.from_findings(result.findings)
            status_text = (
                "Cancelled"
                if cancelled and not result.findings
                else f"Complete ({summary.total_findings} hits)"
            )
            duration_text = f"{result.stats.duration:.1f}s" if result.stats else "-"
            self._update_batch_status(
                result.path,
                status=status_text,
                findings=str(summary.total_findings),
                duration=duration_text,
            )
        if cancelled:
            self.batch_status_label.config(text="Batch cancelled. Partial results retained.")
        elif results:
            total_hits = sum(len(result.findings) for result in results)
            self.batch_status_label.config(
                text=f"Batch complete: {len(results)} jobs | Total findings: {total_hits}"
            )
        else:
            self.batch_status_label.config(text="Batch complete with no processed jobs.")

        self.stop_batch_button.state(["disabled"])
        self.run_batch_button.state(["!disabled"])

    # endregion


def launch() -> None:
    root = tk.Tk()
    SecretScannerGUI(root)
    root.mainloop()


__all__ = ["SecretScannerGUI", "launch"]
