"""Tkinter based GUI for the advanced multi secret scanner."""
from __future__ import annotations

import asyncio
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .scanner import Finding, SecretScanner


SEVERITY_ORDER = ("critical", "high", "medium", "low")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


@dataclass
class ScanSummary:
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int

    @classmethod
    def from_findings(cls, findings: Iterable[Finding]) -> "ScanSummary":
        severity_levels = {severity: 0 for severity in SEVERITY_ORDER}
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
        self.root.geometry("1220x820")
        self.root.configure(bg="#050505")

        self.scanner = SecretScanner()
        self.findings: list[Finding] = []
        self.metadata: dict[str, list[str]] = {"filenames": [], "extensions": []}
        self.current_path: Optional[Path] = None
        self.scan_thread: Optional[threading.Thread] = None
        self.scan_start_time: float | None = None

        self.progress_queue: queue.Queue[tuple[int, int, Optional[Path]]] = queue.Queue()
        self.result_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.batch_progress_queue: queue.Queue[tuple] = queue.Queue()
        self.batch_result_queue: queue.Queue[tuple] = queue.Queue()

        self._configure_style()
        self._init_variables()
        self._build_layout()
        self._start_async_loop()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(200, self._poll_queues)

    # region setup helpers
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
        style.configure("Hacker.TLabelframe", background=primary_bg, foreground=accent)
        style.configure(
            "Hacker.TLabelframe.Label",
            foreground=accent,
            background=primary_bg,
            font=("Consolas", 11, "bold"),
        )
        style.configure("Hacker.TNotebook", background=primary_bg, borderwidth=0)
        style.configure("Hacker.TNotebook.Tab", background="#0f0f0f", foreground=accent, padding=(14, 6))
        style.map(
            "Hacker.TNotebook.Tab",
            background=[("selected", "#0c2f26")],
            foreground=[("selected", accent)],
        )
        style.configure(
            "Hacker.TCheckbutton",
            background=primary_bg,
            foreground=accent,
            font=("Consolas", 11),
        )

    def _init_variables(self) -> None:
        self.path_var = tk.StringVar()
        self.progress_var = tk.DoubleVar(value=0.0)
        self.timer_var = tk.StringVar(value="00:00")
        self.status_var = tk.StringVar(value="Awaiting target directory...")
        self.summary_var = tk.StringVar(value="No scans executed yet.")
        self.search_var = tk.StringVar()

        self.include_hidden_var = tk.BooleanVar(value=self.scanner.include_hidden)
        self.enable_heuristics_var = tk.BooleanVar(value=self.scanner.enable_heuristics)
        self.max_file_size_var = tk.IntVar(value=max(1, self.scanner.max_file_size // (1024 * 1024)))
        self.worker_count_var = tk.IntVar(value=self.scanner.max_workers)
        self.extensions_var = tk.StringVar(value="")
        self.batch_concurrency_var = tk.IntVar(value=min(4, self.scanner.max_workers))

        self.severity_filters: dict[str, tk.BooleanVar] = {
            level: tk.BooleanVar(value=True) for level in SEVERITY_ORDER
        }

        self.batch_results: dict[str, list[Finding]] = {}
        self.batch_metadata: dict[str, dict[str, list[str]]] = {}

        self.search_var.trace_add("write", lambda *_: self._refresh_tree())

    def _build_layout(self) -> None:
        self.notebook = ttk.Notebook(self.root, style="Hacker.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=12, pady=12)

        self.single_frame = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.batch_frame = ttk.Frame(self.notebook, style="Hacker.TFrame")
        self.notebook.add(self.single_frame, text="Single Scan")
        self.notebook.add(self.batch_frame, text="Batch Operations")

        self._build_single_tab()
        self._build_batch_tab()

    def _build_single_tab(self) -> None:
        header_frame = ttk.Frame(self.single_frame, style="Hacker.TFrame")
        header_frame.pack(fill="x", pady=18, padx=16)

        title_label = ttk.Label(
            header_frame,
            text=r"// Advanced Multi Secret Scanner \\",
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

        path_entry = ttk.Entry(header_frame, textvariable=self.path_var, width=70, style="Hacker.TEntry")
        path_entry.grid(row=0, column=1, padx=12, sticky="ew")

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

        export_button = ttk.Button(
            header_frame,
            text="Export Findings",
            style="Hacker.TButton",
            command=self.export_findings,
        )
        export_button.grid(row=1, column=2, padx=(12, 0), pady=(8, 0))

        settings_frame = ttk.Labelframe(
            self.single_frame,
            text="Scan Settings",
            style="Hacker.TLabelframe",
        )
        settings_frame.pack(fill="x", padx=16, pady=(0, 12))

        include_hidden = ttk.Checkbutton(
            settings_frame,
            text="Include hidden",
            variable=self.include_hidden_var,
            style="Hacker.TCheckbutton",
            command=self._apply_settings,
        )
        include_hidden.grid(row=0, column=0, padx=6, pady=6, sticky="w")

        heuristics_toggle = ttk.Checkbutton(
            settings_frame,
            text="Enable heuristics",
            variable=self.enable_heuristics_var,
            style="Hacker.TCheckbutton",
            command=self._apply_settings,
        )
        heuristics_toggle.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        ttk.Label(settings_frame, text="Max file size (MB):").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        size_spin = ttk.Spinbox(
            settings_frame,
            from_=1,
            to=512,
            textvariable=self.max_file_size_var,
            width=6,
            command=self._apply_settings,
        )
        size_spin.grid(row=1, column=1, padx=6, pady=6, sticky="w")

        ttk.Label(settings_frame, text="Max workers:").grid(row=1, column=2, padx=6, pady=6, sticky="w")
        worker_spin = ttk.Spinbox(
            settings_frame,
            from_=1,
            to=64,
            textvariable=self.worker_count_var,
            width=6,
            command=self._apply_settings,
        )
        worker_spin.grid(row=1, column=3, padx=6, pady=6, sticky="w")

        ttk.Label(settings_frame, text="Extensions filter (comma separated):").grid(
            row=2, column=0, columnspan=2, padx=6, pady=6, sticky="w"
        )
        extensions_entry = ttk.Entry(settings_frame, textvariable=self.extensions_var, width=60, style="Hacker.TEntry")
        extensions_entry.grid(row=2, column=2, columnspan=2, padx=6, pady=6, sticky="ew")
        extensions_entry.bind("<Return>", lambda _event: self._apply_settings())
        settings_frame.columnconfigure(3, weight=1)

        filter_frame = ttk.Labelframe(
            self.single_frame,
            text="Result Filters",
            style="Hacker.TLabelframe",
        )
        filter_frame.pack(fill="x", padx=16, pady=(0, 12))

        ttk.Label(filter_frame, text="Search:").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=40, style="Hacker.TEntry")
        search_entry.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        severity_frame = ttk.Frame(filter_frame, style="Hacker.TFrame")
        severity_frame.grid(row=0, column=2, padx=6, pady=6, sticky="w")

        for index, severity in enumerate(SEVERITY_ORDER):
            check = ttk.Checkbutton(
                severity_frame,
                text=severity.upper(),
                variable=self.severity_filters[severity],
                style="Hacker.TCheckbutton",
                command=self._refresh_tree,
            )
            check.grid(row=0, column=index, padx=4)

        self.progress_bar = ttk.Progressbar(
            self.single_frame,
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

        status_frame = ttk.Frame(self.single_frame, style="Hacker.TFrame")
        status_frame.pack(fill="x", padx=18, pady=10)

        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, font=("Consolas", 12))
        self.status_label.pack(side="left")

        self.timer_label = ttk.Label(status_frame, textvariable=self.timer_var, font=("Consolas", 12, "bold"))
        self.timer_label.pack(side="right")

        results_frame = ttk.Frame(self.single_frame, style="Hacker.TFrame")
        results_frame.pack(fill="both", expand=True, padx=18, pady=(6, 12))

        columns = ("severity", "pattern", "file", "line", "snippet")
        self.tree = ttk.Treeview(
            results_frame,
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
        self.tree.column("pattern", width=220)
        self.tree.column("file", width=440)
        self.tree.column("line", width=80, anchor="center")
        self.tree.column("snippet", width=440)
        self.tree.pack(fill="both", expand=True, side="left")
        self.tree.bind("<Double-1>", self._open_selected_file)

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        summary_frame = ttk.Frame(self.single_frame, style="Hacker.TFrame")
        summary_frame.pack(fill="x", padx=18, pady=(0, 12))

        self.summary_label = ttk.Label(summary_frame, textvariable=self.summary_var, font=("Consolas", 12))
        self.summary_label.pack(side="left", anchor="w")

        metadata_frame = ttk.Labelframe(
            self.single_frame,
            text="Metadata Insights",
            style="Hacker.TLabelframe",
        )
        metadata_frame.pack(fill="x", padx=16, pady=(0, 18))

        meta_columns = ("category", "count", "example")
        self.metadata_tree = ttk.Treeview(
            metadata_frame,
            columns=meta_columns,
            show="headings",
            style="Hacker.Treeview",
            height=4,
        )
        self.metadata_tree.heading("category", text="Category")
        self.metadata_tree.heading("count", text="Count")
        self.metadata_tree.heading("example", text="Example")
        self.metadata_tree.column("category", width=200)
        self.metadata_tree.column("count", width=80, anchor="center")
        self.metadata_tree.column("example", width=520)
        self.metadata_tree.pack(fill="x", padx=8, pady=6)

        self.metadata_button = ttk.Button(
            metadata_frame,
            text="View detailed metadata",
            style="Hacker.TButton",
            command=self._show_metadata_details,
        )
        self.metadata_button.pack(anchor="e", padx=8, pady=(0, 6))

    def _build_batch_tab(self) -> None:
        description = ttk.Label(
            self.batch_frame,
            text="Queue multiple codebases and unleash concurrent hunts.",
            font=("Consolas", 14),
            foreground="#0aff9d",
        )
        description.pack(anchor="w", padx=16, pady=(16, 6))

        queue_frame = ttk.Frame(self.batch_frame, style="Hacker.TFrame")
        queue_frame.pack(fill="x", padx=16)

        self.batch_listbox = tk.Listbox(
            queue_frame,
            height=8,
            bg="#0b0f0d",
            fg="#57ffb0",
            selectbackground="#084d3d",
            selectforeground="#0aff9d",
            highlightthickness=1,
            highlightcolor="#0aff9d",
            relief="flat",
            font=("Consolas", 11),
        )
        self.batch_listbox.grid(row=0, column=0, sticky="nsew")
        queue_frame.columnconfigure(0, weight=1)

        list_scroll = ttk.Scrollbar(queue_frame, orient="vertical", command=self.batch_listbox.yview)
        list_scroll.grid(row=0, column=1, sticky="ns")
        self.batch_listbox.configure(yscrollcommand=list_scroll.set)

        controls_frame = ttk.Frame(self.batch_frame, style="Hacker.TFrame")
        controls_frame.pack(fill="x", padx=16, pady=12)

        self.add_batch_button = ttk.Button(
            controls_frame,
            text="Add directory",
            style="Hacker.TButton",
            command=self.add_batch_directory,
        )
        self.add_batch_button.grid(row=0, column=0, padx=6)

        self.remove_batch_button = ttk.Button(
            controls_frame,
            text="Remove selected",
            style="Hacker.TButton",
            command=self.remove_selected_batch_directory,
        )
        self.remove_batch_button.grid(row=0, column=1, padx=6)

        self.clear_batch_button = ttk.Button(
            controls_frame,
            text="Clear queue",
            style="Hacker.TButton",
            command=self.clear_batch_queue,
        )
        self.clear_batch_button.grid(row=0, column=2, padx=6)

        ttk.Label(controls_frame, text="Concurrent jobs:").grid(row=0, column=3, padx=6)
        concurrency_spin = ttk.Spinbox(
            controls_frame,
            from_=1,
            to=16,
            textvariable=self.batch_concurrency_var,
            width=6,
        )
        concurrency_spin.grid(row=0, column=4, padx=6)

        self.start_batch_button = ttk.Button(
            controls_frame,
            text="Launch batch scan",
            style="Hacker.TButton",
            command=self.start_batch_scan,
        )
        self.start_batch_button.grid(row=0, column=5, padx=6)

        controls_frame.columnconfigure(5, weight=1)

        self.batch_progress_var = tk.DoubleVar(value=0.0)
        batch_progress = ttk.Progressbar(
            self.batch_frame,
            orient="horizontal",
            mode="determinate",
            variable=self.batch_progress_var,
            style="green.Horizontal.TProgressbar",
        )
        batch_progress.pack(fill="x", padx=20, pady=(6, 0))

        self.batch_file_status = tk.StringVar(value="Idle")
        self.batch_job_status = tk.StringVar(value="No jobs running.")

        batch_status_frame = ttk.Frame(self.batch_frame, style="Hacker.TFrame")
        batch_status_frame.pack(fill="x", padx=16, pady=8)
        ttk.Label(batch_status_frame, textvariable=self.batch_file_status).pack(anchor="w")
        ttk.Label(batch_status_frame, textvariable=self.batch_job_status).pack(anchor="w")

        result_columns = ("path", "total", "critical", "high", "medium", "low")
        self.batch_tree = ttk.Treeview(
            self.batch_frame,
            columns=result_columns,
            show="headings",
            style="Hacker.Treeview",
            height=12,
        )
        headings = {
            "path": "Repository",
            "total": "Findings",
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }
        for col, text in headings.items():
            self.batch_tree.heading(col, text=text)
            self.batch_tree.column(col, anchor="w")
        self.batch_tree.column("path", width=480)
        self.batch_tree.column("total", width=100, anchor="center")
        self.batch_tree.column("critical", width=100, anchor="center")
        self.batch_tree.column("high", width=100, anchor="center")
        self.batch_tree.column("medium", width=100, anchor="center")
        self.batch_tree.column("low", width=100, anchor="center")
        self.batch_tree.pack(fill="both", expand=True, padx=16, pady=(4, 12))
        self.batch_tree.bind("<<TreeviewSelect>>", self._on_batch_selection)

        detail_frame = ttk.Labelframe(
            self.batch_frame,
            text="Batch job details",
            style="Hacker.TLabelframe",
        )
        detail_frame.pack(fill="both", expand=False, padx=16, pady=(0, 16))

        self.batch_detail_text = tk.Text(
            detail_frame,
            height=8,
            bg="#0b0f0d",
            fg="#57ffb0",
            insertbackground="#0aff9d",
            wrap="word",
            font=("Consolas", 11),
        )
        self.batch_detail_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.batch_detail_text.config(state="disabled")

        self._batch_control_widgets = [
            self.add_batch_button,
            self.remove_batch_button,
            self.clear_batch_button,
            self.start_batch_button,
        ]

    def _start_async_loop(self) -> None:
        self.async_loop = asyncio.new_event_loop()

        def run_loop() -> None:
            asyncio.set_event_loop(self.async_loop)
            self.async_loop.run_forever()

        self.loop_thread = threading.Thread(target=run_loop, daemon=True)
        self.loop_thread.start()

    # endregion

    # region event loop integration
    def _poll_queues(self) -> None:
        while not self.progress_queue.empty():
            current, total, path = self.progress_queue.get()
            progress = (current / total) * 100 if total else 0
            self.progress_var.set(progress)
            if path:
                display = str(path)[-100:]
                self.status_var.set(f"Scanning {display}")
            else:
                self.status_var.set("Scan complete")

        while not self.result_queue.empty():
            kind, payload = self.result_queue.get()
            if kind == "error":
                messagebox.showerror("Scan failed", str(payload))
            elif kind == "result":
                findings, metadata = payload  # type: ignore[misc]
                self.findings = findings
                self.metadata = metadata
                self._display_results()
            self.scan_thread = None

        while not self.batch_progress_queue.empty():
            event = self.batch_progress_queue.get()
            if not event:
                continue
            tag = event[0]
            if tag == "file":
                _, root, current, total, path = event
                percent = (current / total) * 100 if total else 0
                snippet = Path(path).name if path else "finalizing"
                self.batch_file_status.set(f"[{root}] {current}/{total} files - {snippet}")
                self.batch_progress_var.set(percent)
            elif tag == "job":
                _, completed, total_jobs, path = event
                self.batch_job_status.set(f"Completed {completed}/{total_jobs} - {path}")
            elif tag == "status":
                _, message = event
                self.batch_job_status.set(message)

        while not self.batch_result_queue.empty():
            event = self.batch_result_queue.get()
            tag = event[0]
            if tag == "result":
                _, results, metadata_map = event
                self._populate_batch_results(results, metadata_map)
            elif tag == "error":
                _, message = event
                messagebox.showerror("Batch scan failed", str(message))
            elif tag == "done":
                self._set_batch_controls_state(False)
                self.batch_file_status.set("Idle")
                if not self.batch_tree.get_children():
                    self.batch_job_status.set("No findings detected across batch.")
                else:
                    self.batch_job_status.set("Batch finished. Review results below.")

        self.root.after(200, self._poll_queues)

    def _on_close(self) -> None:
        try:
            self.async_loop.call_soon_threadsafe(self.async_loop.stop)
        except RuntimeError:
            pass
        self.root.destroy()

    # endregion

    # region scanner helpers
    def _apply_settings(self) -> None:
        try:
            max_size_mb = max(1, int(self.max_file_size_var.get()))
        except (tk.TclError, ValueError):
            max_size_mb = 4
        try:
            workers = max(1, int(self.worker_count_var.get()))
        except (tk.TclError, ValueError):
            workers = self.scanner.max_workers

        extensions = [ext.strip() for ext in self.extensions_var.get().split(",") if ext.strip()]
        normalized_ext = [ext if ext.startswith(".") else f".{ext}" for ext in extensions]

        self.scanner = SecretScanner(
            max_file_size=max_size_mb * 1024 * 1024,
            include_hidden=self.include_hidden_var.get(),
            extensions=normalized_ext or None,
            max_workers=workers,
            enable_heuristics=self.enable_heuristics_var.get(),
        )

    def _create_scanner(self) -> SecretScanner:
        self._apply_settings()
        return self.scanner

    def _gather_scanner_config(self) -> dict[str, object]:
        self._apply_settings()
        return {
            "max_file_size": self.scanner.max_file_size,
            "include_hidden": self.scanner.include_hidden,
            "extensions": list(self.scanner.extensions) if self.scanner.extensions else None,
            "max_workers": self.scanner.max_workers,
            "enable_heuristics": self.scanner.enable_heuristics,
        }

    # endregion

    # region single scan actions
    def select_directory(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.path_var.set(directory)
            self.current_path = Path(directory)
            self.status_var.set(f"Target locked: {directory}")

    def trigger_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan in progress", "Please wait for the current scan to complete.")
            return

        path_value = self.path_var.get().strip()
        if not path_value:
            messagebox.showwarning("Missing target", "Select a directory to scan.")
            return

        path = Path(path_value)
        if not path.exists() or not path.is_dir():
            messagebox.showerror("Invalid directory", "The selected path is not a directory.")
            return

        self.current_path = path
        self.findings.clear()
        self.metadata = {"filenames": [], "extensions": []}
        self.tree.delete(*self.tree.get_children())
        self.metadata_tree.delete(*self.metadata_tree.get_children())
        self.progress_var.set(0)
        self.status_var.set("Initializing deep scan...")
        self.summary_var.set("Running scan...")

        self.scan_thread = threading.Thread(target=self._run_scan_worker, args=(path,), daemon=True)
        self.scan_thread.start()
        self.scan_start_time = time.time()
        self._update_timer()

    def _run_scan_worker(self, path: Path) -> None:
        scanner = self._create_scanner()

        def on_progress(current: int, total: int, item: Optional[Path]) -> None:
            self.progress_queue.put((current, total, item))

        try:
            findings = scanner.scan_directory(path, progress_callback=on_progress)
            metadata = scanner.collect_metadata(path)
        except Exception as exc:  # noqa: BLE001
            self.result_queue.put(("error", exc))
            return

        self.result_queue.put(("result", (findings, metadata)))

    def _update_timer(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive() and self.scan_start_time is not None:
            elapsed = int(time.time() - self.scan_start_time)
            minutes, seconds = divmod(elapsed, 60)
            self.timer_var.set(f"{minutes:02d}:{seconds:02d}")
            self.root.after(1000, self._update_timer)
        elif self.scan_start_time is not None:
            elapsed = int(time.time() - self.scan_start_time)
            minutes, seconds = divmod(elapsed, 60)
            self.timer_var.set(f"{minutes:02d}:{seconds:02d}")
            self.scan_start_time = None

    def _display_results(self) -> None:
        self._refresh_tree()
        summary = ScanSummary.from_findings(self.findings)
        heuristic_hits = sum(1 for finding in self.findings if "entropy" in finding.pattern.name.lower())
        meta_text = self._format_metadata_summary()
        self.summary_var.set(
            (
                f"Findings: {summary.total_findings} | Critical: {summary.critical} | High: {summary.high} | "
                f"Medium: {summary.medium} | Low: {summary.low} | Heuristic hits: {heuristic_hits} | {meta_text}"
            )
        )
        if not self.findings:
            self.status_var.set("Scan complete - no indicators found.")
        else:
            self.status_var.set("Scan complete - review flagged entries.")
        self._update_metadata_panel()

    def _refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        search = self.search_var.get().lower().strip()
        allowed = {
            severity
            for severity, var in self.severity_filters.items()
            if var.get()
        }
        for finding in self.findings:
            severity = finding.pattern.severity.lower()
            severity_key = severity if severity in self.severity_filters else "medium"
            if allowed and severity_key not in allowed:
                continue
            snippet = finding.line.strip()
            if len(snippet) > 160:
                snippet = snippet[:157] + "..."
            row_text = " ".join([finding.pattern.name, str(finding.file_path), snippet]).lower()
            if search and search not in row_text:
                continue
            self.tree.insert(
                "",
                "end",
                values=(
                    severity.upper(),
                    finding.pattern.name,
                    str(finding.file_path),
                    finding.line_number,
                    snippet,
                ),
            )

    def _format_metadata_summary(self) -> str:
        file_count = len(self.metadata.get("filenames", []))
        ext_count = len(self.metadata.get("extensions", []))
        parts: list[str] = []
        if file_count:
            parts.append(f"Sensitive names: {file_count}")
        if ext_count:
            parts.append(f"Sensitive extensions: {ext_count}")
        return " | ".join(parts) if parts else "No sensitive file metadata."

    def _update_metadata_panel(self) -> None:
        self.metadata_tree.delete(*self.metadata_tree.get_children())
        filenames = self.metadata.get("filenames", [])
        extensions = self.metadata.get("extensions", [])
        self.metadata_tree.insert(
            "",
            "end",
            values=(
                "Sensitive filenames",
                len(filenames),
                filenames[0] if filenames else "-",
            ),
        )
        self.metadata_tree.insert(
            "",
            "end",
            values=(
                "Sensitive extensions",
                len(extensions),
                extensions[0] if extensions else "-",
            ),
        )

    def _show_metadata_details(self) -> None:
        if not any(self.metadata.values()):
            messagebox.showinfo("Metadata", "No metadata available yet.")
            return

        window = tk.Toplevel(self.root)
        window.title("Metadata details")
        window.configure(bg="#050505")
        text = tk.Text(
            window,
            bg="#0b0f0d",
            fg="#57ffb0",
            insertbackground="#0aff9d",
            wrap="word",
            font=("Consolas", 11),
        )
        text.pack(fill="both", expand=True)

        def write_section(title: str, entries: list[str]) -> None:
            text.insert("end", f"{title}\n", ("title",))
            if entries:
                for entry in entries:
                    text.insert("end", f"  - {entry}\n")
            else:
                text.insert("end", "  (none)\n")
            text.insert("end", "\n")

        write_section("Sensitive filenames", self.metadata.get("filenames", []))
        write_section("Sensitive extensions", self.metadata.get("extensions", []))
        text.tag_configure("title", foreground="#0aff9d", font=("Consolas", 12, "bold"))
        text.config(state="disabled")

    def _open_selected_file(self, _event: object) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        if not values:
            return
        file_path = Path(values[2])
        if not file_path.exists():
            messagebox.showwarning("File missing", f"Cannot locate {file_path}.")
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(file_path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(file_path)])
            else:
                subprocess.Popen(["xdg-open", str(file_path)])
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Open failed", str(exc))

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

    # endregion

    # region batch actions
    def _set_batch_controls_state(self, running: bool) -> None:
        state = tk.DISABLED if running else tk.NORMAL
        for widget in self._batch_control_widgets:
            widget.config(state=state)
        if running:
            self.batch_job_status.set("Launching batch scan...")
        else:
            self.batch_progress_var.set(0)

    def add_batch_directory(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.batch_listbox.insert(tk.END, directory)

    def remove_selected_batch_directory(self) -> None:
        for index in reversed(self.batch_listbox.curselection()):
            self.batch_listbox.delete(index)

    def clear_batch_queue(self) -> None:
        self.batch_listbox.delete(0, tk.END)

    def start_batch_scan(self) -> None:
        if any(widget.cget("state") == tk.DISABLED for widget in self._batch_control_widgets):
            messagebox.showinfo("Batch running", "Please wait for the current batch to finish.")
            return

        directories = [self.batch_listbox.get(i) for i in range(self.batch_listbox.size())]
        if not directories:
            messagebox.showinfo("Batch queue empty", "Add directories to the queue first.")
            return

        paths = [Path(path) for path in directories if Path(path).exists()]
        if not paths:
            messagebox.showerror("Invalid queue", "All queued directories are invalid or missing.")
            return

        self.batch_results.clear()
        self.batch_metadata.clear()
        self.batch_tree.delete(*self.batch_tree.get_children())
        self.batch_detail_text.config(state="normal")
        self.batch_detail_text.delete("1.0", tk.END)
        self.batch_detail_text.config(state="disabled")

        while not self.batch_progress_queue.empty():
            self.batch_progress_queue.get_nowait()
        while not self.batch_result_queue.empty():
            self.batch_result_queue.get_nowait()

        self.batch_progress_var.set(0)
        self.batch_file_status.set("Initializing batch run...")
        self.batch_job_status.set(f"Queued {len(paths)} repositories.")

        self._set_batch_controls_state(True)

        config = self._gather_scanner_config()
        try:
            concurrency = max(1, int(self.batch_concurrency_var.get()))
        except (tk.TclError, ValueError):
            concurrency = 1

        def submit() -> None:
            asyncio.create_task(self._execute_batch_scan(paths, config, concurrency))

        self.async_loop.call_soon_threadsafe(submit)

    async def _execute_batch_scan(
        self,
        paths: list[Path],
        config: dict[str, object],
        concurrency: int,
    ) -> None:
        self.batch_progress_queue.put(("status", f"Launching {len(paths)} concurrent jobs..."))
        try:
            scanner = SecretScanner(**config)

            def file_progress(root: Path, current: int, total: int, path: Optional[Path]) -> None:
                self.batch_progress_queue.put(
                    (
                        "file",
                        str(root),
                        current,
                        total,
                        str(path) if path else None,
                    )
                )

            def job_progress(completed: int, total_jobs: int, root: Path) -> None:
                self.batch_progress_queue.put(("job", completed, total_jobs, str(root)))

            results = await scanner.scan_batch_async(
                paths,
                file_progress_callback=file_progress,
                job_progress_callback=job_progress,
                max_concurrent=concurrency,
            )

            metadata_map: dict[str, dict[str, list[str]]] = {}
            for root in results:
                metadata = await asyncio.to_thread(scanner.collect_metadata, root)
                metadata_map[str(root)] = metadata

            str_results = {str(root): findings for root, findings in results.items()}
            self.batch_result_queue.put(("result", str_results, metadata_map))
        except Exception as exc:  # noqa: BLE001
            self.batch_result_queue.put(("error", exc))
        finally:
            self.batch_result_queue.put(("done",))

    def _populate_batch_results(
        self,
        results: dict[str, list[Finding]],
        metadata_map: dict[str, dict[str, list[str]]],
    ) -> None:
        self.batch_results = results
        self.batch_metadata = metadata_map
        self.batch_tree.delete(*self.batch_tree.get_children())

        for path_str in sorted(results):
            findings = results[path_str]
            summary = ScanSummary.from_findings(findings)
            self.batch_tree.insert(
                "",
                "end",
                iid=path_str,
                values=(
                    path_str,
                    summary.total_findings,
                    summary.critical,
                    summary.high,
                    summary.medium,
                    summary.low,
                ),
            )

        if results:
            first = self.batch_tree.get_children()[0]
            self.batch_tree.selection_set(first)
            self._on_batch_selection()

    def _on_batch_selection(self, _event: object | None = None) -> None:
        selection = self.batch_tree.selection()
        if not selection:
            return
        path_str = selection[0]
        findings = self.batch_results.get(path_str, [])
        metadata = self.batch_metadata.get(path_str, {"filenames": [], "extensions": []})
        summary = ScanSummary.from_findings(findings)
        heuristic_hits = sum(1 for finding in findings if "entropy" in finding.pattern.name.lower())

        lines = [
            f"Repository: {path_str}",
            f"Total findings: {summary.total_findings}",
            f"Critical: {summary.critical} | High: {summary.high} | Medium: {summary.medium} | Low: {summary.low}",
            f"Heuristic hits: {heuristic_hits}",
            "",
        ]

        if findings:
            lines.append("Top indicators:")
            top = sorted(
                findings,
                key=lambda f: (SEVERITY_RANK.get(f.pattern.severity, len(SEVERITY_ORDER)), f.pattern.name),
            )[:10]
            for finding in top:
                lines.append(
                    f"  - [{finding.pattern.severity.upper()}] {finding.pattern.name} :: {finding.file_path} (line {finding.line_number})"
                )
            if len(findings) > 10:
                lines.append(f"  ... (+{len(findings) - 10} more)")
            lines.append("")

        filenames = metadata.get("filenames", [])
        extensions = metadata.get("extensions", [])
        lines.append(f"Sensitive filenames ({len(filenames)}):")
        if filenames:
            preview = filenames[:10]
            lines.extend(f"  - {item}" for item in preview)
            if len(filenames) > 10:
                lines.append(f"  ... (+{len(filenames) - 10} more)")
        else:
            lines.append("  (none)")

        lines.append("")
        lines.append(f"Sensitive extensions ({len(extensions)}):")
        if extensions:
            preview_ext = extensions[:10]
            lines.extend(f"  - {item}" for item in preview_ext)
            if len(extensions) > 10:
                lines.append(f"  ... (+{len(extensions) - 10} more)")
        else:
            lines.append("  (none)")

        self._write_batch_detail(lines)

    def _write_batch_detail(self, lines: list[str]) -> None:
        self.batch_detail_text.config(state="normal")
        self.batch_detail_text.delete("1.0", tk.END)
        self.batch_detail_text.insert("end", "\n".join(lines))
        self.batch_detail_text.config(state="disabled")

    # endregion


def launch() -> None:
    root = tk.Tk()
    SecretScannerGUI(root)
    root.mainloop()


__all__ = ["SecretScannerGUI", "launch"]
