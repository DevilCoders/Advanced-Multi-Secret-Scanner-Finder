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

from .scanner import Finding, SecretScanner


@dataclass
class ScanSummary:
    total_findings: int
    critical: int
    high: int
    medium: int
    entropy_hits: int
    duration: float

    @classmethod
    def from_findings(cls, findings: Iterable[Finding], *, duration: float = 0.0) -> ScanSummary:
        severity_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total = 0
        entropy_hits = 0
        for finding in findings:
            total += 1
            severity_levels[finding.pattern.severity] = (
                severity_levels.get(finding.pattern.severity, 0) + 1
            )
            if finding.entropy is not None:
                entropy_hits += 1
        return cls(
            total_findings=total,
            critical=severity_levels.get("critical", 0),
            high=severity_levels.get("high", 0),
            medium=severity_levels.get("medium", 0),
            entropy_hits=entropy_hits,
            duration=duration,
        )


class SecretScannerGUI:
    """Main GUI application class."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Advanced Multi Secret Scanner")
        self.root.geometry("1240x780")
        self.root.configure(bg="#050505")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.scanner = SecretScanner()
        self.findings: list[Finding] = []
        self.metadata_cache: dict[str, list[str]] = {
            "filenames": [],
            "extensions": [],
            "env_files": [],
            "large_files": [],
            "extension_summary": [],
        }
        self.tree_item_to_finding: dict[str, Finding] = {}
        self.current_path: Optional[Path] = None
        self.scan_task: Optional[asyncio.Future] = None
        self.scan_in_progress = False
        self.scan_start_time: float | None = None
        self.timer_job: str | None = None
        self.last_scan_duration: float = 0.0
        self.batch_targets: list[Path] = []

        self.loop = asyncio.new_event_loop()
        self.loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.loop_thread.start()

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
        style.configure(
            "Hacker.TCheckbutton",
            background=primary_bg,
            foreground=text_color,
            font=("Consolas", 11),
        )
        style.map("Hacker.TCheckbutton", background=[("selected", "#0a1f1a")])
        style.configure(
            "Hacker.TSpinbox",
            fieldbackground="#0f1512",
            foreground=accent,
            insertcolor=accent,
            arrowsize=14,
        )
        style.configure("Hacker.TLabelframe", background=primary_bg, foreground=accent, font=("Consolas", 12, "bold"))
        style.configure("Hacker.TLabelframe.Label", background=primary_bg, foreground=accent, font=("Consolas", 12, "bold"))
        style.configure("Hacker.TNotebook", background=primary_bg, borderwidth=0)
        style.configure("Hacker.TNotebook.Tab", background="#06120f", foreground=accent, font=("Consolas", 11, "bold"))
        style.map("Hacker.TNotebook.Tab", background=[("selected", "#0a3125")], foreground=[("selected", accent)])

    def _build_layout(self) -> None:
        self.header_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        self.header_frame.pack(fill="x", pady=18, padx=16)

        title_label = ttk.Label(
            self.header_frame,
            text="// Advanced Multi Secret Scanner \\",
            font=("Consolas", 20, "bold"),
        )
        title_label.grid(row=0, column=0, sticky="w")

        subtitle_label = ttk.Label(
            self.header_frame,
            text="Harden your codebase. Hunt for secrets like a pro hacker.",
            font=("Consolas", 12),
            foreground="#0aff9d",
        )
        subtitle_label.grid(row=1, column=0, sticky="w", pady=(6, 0))

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

        control_button_frame = ttk.Frame(self.header_frame, style="Hacker.TFrame")
        control_button_frame.grid(row=1, column=1, columnspan=2, sticky="e", pady=(8, 0))
        control_button_frame.columnconfigure(3, weight=1)

        scan_button = ttk.Button(
            control_button_frame,
            text="Initiate Scan",
            style="Hacker.TButton",
            command=self.trigger_scan,
        )
        scan_button.grid(row=0, column=0, padx=(0, 8))

        add_batch_button = ttk.Button(
            control_button_frame,
            text="Add to Batch",
            style="Hacker.TButton",
            command=self.add_to_batch,
        )
        add_batch_button.grid(row=0, column=1, padx=(0, 8))

        run_batch_button = ttk.Button(
            control_button_frame,
            text="Run Batch",
            style="Hacker.TButton",
            command=self.run_batch,
        )
        run_batch_button.grid(row=0, column=2, padx=(0, 8))

        export_button = ttk.Button(
            control_button_frame,
            text="Export Findings",
            style="Hacker.TButton",
            command=self.export_findings,
        )
        export_button.grid(row=0, column=4)

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

        self._build_control_panel()
        self._build_batch_panel()
        self._build_results_panel()

        summary_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        summary_frame.pack(fill="x", padx=18, pady=(0, 18))

        self.summary_label = ttk.Label(
            summary_frame,
            text="No scans executed yet.",
            font=("Consolas", 12),
        )
        self.summary_label.pack(side="left")

    def _build_control_panel(self) -> None:
        control_frame = ttk.LabelFrame(self.root, text="Scan Controls", style="Hacker.TLabelframe")
        control_frame.pack(fill="x", padx=18, pady=(0, 12))
        control_frame.columnconfigure(5, weight=1)

        self.include_hidden_var = tk.BooleanVar(value=False)
        include_hidden_check = ttk.Checkbutton(
            control_frame,
            text="Include hidden files",
            style="Hacker.TCheckbutton",
            variable=self.include_hidden_var,
            command=self._apply_options,
        )
        include_hidden_check.grid(row=0, column=0, sticky="w", padx=(6, 12), pady=6)

        self.enable_entropy_var = tk.BooleanVar(value=True)
        entropy_check = ttk.Checkbutton(
            control_frame,
            text="High entropy detection",
            style="Hacker.TCheckbutton",
            variable=self.enable_entropy_var,
            command=self._apply_options,
        )
        entropy_check.grid(row=0, column=1, sticky="w", padx=(0, 12), pady=6)

        ttk.Label(control_frame, text="Max file size (MB):").grid(row=0, column=2, sticky="w")
        self.max_file_size_var = tk.IntVar(value=4)
        max_size_spin = ttk.Spinbox(
            control_frame,
            from_=1,
            to=128,
            increment=1,
            width=6,
            textvariable=self.max_file_size_var,
            style="Hacker.TSpinbox",
            command=self._apply_options,
        )
        max_size_spin.grid(row=0, column=3, sticky="w", padx=(0, 12))

        ttk.Label(control_frame, text="Worker threads:").grid(row=0, column=4, sticky="w")
        self.worker_count_var = tk.IntVar(value=self.scanner.max_workers)
        worker_spin = ttk.Spinbox(
            control_frame,
            from_=1,
            to=max(self.scanner.max_workers * 2, 16),
            increment=1,
            width=6,
            textvariable=self.worker_count_var,
            style="Hacker.TSpinbox",
            command=self._apply_options,
        )
        worker_spin.grid(row=0, column=5, sticky="w", padx=(0, 12))

        ttk.Label(control_frame, text="Extensions filter (csv):").grid(row=1, column=0, sticky="w", padx=(6, 12))
        self.extension_var = tk.StringVar(value="")
        extension_entry = ttk.Entry(control_frame, textvariable=self.extension_var, style="Hacker.TEntry")
        extension_entry.grid(row=1, column=1, columnspan=2, sticky="ew", padx=(0, 12))
        extension_entry.bind("<Return>", lambda _event: self._apply_options())

        ttk.Label(control_frame, text="Search findings:").grid(row=1, column=3, sticky="w")
        self.search_var = tk.StringVar(value="")
        search_entry = ttk.Entry(control_frame, textvariable=self.search_var, style="Hacker.TEntry")
        search_entry.grid(row=1, column=4, columnspan=2, sticky="ew", padx=(0, 12))
        self.search_var.trace_add("write", lambda *_: self._refresh_tree())

        severity_frame = ttk.Frame(control_frame, style="Hacker.TFrame")
        severity_frame.grid(row=2, column=0, columnspan=6, sticky="w", pady=(6, 2))
        ttk.Label(severity_frame, text="Severity filter:").pack(side="left", padx=(0, 12))

        self.severity_vars: dict[str, tk.BooleanVar] = {}
        for severity, default in ("critical", True), ("high", True), ("medium", True), ("low", True):
            var = tk.BooleanVar(value=default)
            chk = ttk.Checkbutton(
                severity_frame,
                text=severity.capitalize(),
                variable=var,
                style="Hacker.TCheckbutton",
                command=self._refresh_tree,
            )
            chk.pack(side="left", padx=(0, 12))
            self.severity_vars[severity] = var

        reset_button = ttk.Button(
            control_frame,
            text="Reset filters",
            style="Hacker.TButton",
            command=self._reset_filters,
        )
        reset_button.grid(row=2, column=5, sticky="e", pady=(6, 4))

    def _build_batch_panel(self) -> None:
        batch_frame = ttk.LabelFrame(self.root, text="Batch Queue", style="Hacker.TLabelframe")
        batch_frame.pack(fill="x", padx=18, pady=(0, 12))

        columns = ("target",)
        self.batch_tree = ttk.Treeview(
            batch_frame,
            columns=columns,
            show="headings",
            height=4,
            style="Hacker.Treeview",
        )
        self.batch_tree.heading("target", text="Target Directory")
        self.batch_tree.column("target", width=860, anchor="w")
        self.batch_tree.pack(fill="x", side="left", padx=(6, 6), pady=6, expand=True)

        scrollbar = ttk.Scrollbar(batch_frame, orient="vertical", command=self.batch_tree.yview)
        scrollbar.pack(side="left", fill="y", pady=6)
        self.batch_tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(batch_frame, style="Hacker.TFrame")
        button_frame.pack(side="left", padx=(12, 6), pady=6)

        remove_button = ttk.Button(
            button_frame,
            text="Remove Selected",
            style="Hacker.TButton",
            command=self.remove_from_batch,
        )
        remove_button.pack(fill="x", pady=(0, 6))

        clear_button = ttk.Button(
            button_frame,
            text="Clear Queue",
            style="Hacker.TButton",
            command=self.clear_batch,
        )
        clear_button.pack(fill="x")

        self.batch_status_label = ttk.Label(batch_frame, text="No batch queued.")
        self.batch_status_label.pack(side="left", padx=12)

    def _build_results_panel(self) -> None:
        self.notebook = ttk.Notebook(self.root, style="Hacker.TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(6, 18))

        findings_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")
        metadata_tab = ttk.Frame(self.notebook, style="Hacker.TFrame")

        self.notebook.add(findings_tab, text="Findings")
        self.notebook.add(metadata_tab, text="Metadata")

        findings_container = ttk.Frame(findings_tab, style="Hacker.TFrame")
        findings_container.pack(fill="both", expand=True)

        columns = ("severity", "pattern", "file", "line", "snippet")
        self.tree = ttk.Treeview(
            findings_container,
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
        self.tree.column("file", width=520)
        self.tree.column("line", width=80, anchor="center")
        self.tree.column("snippet", width=420)
        self.tree.pack(fill="both", expand=True, side="left", padx=(0, 6), pady=(6, 6))

        scrollbar = ttk.Scrollbar(findings_container, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="left", fill="y", pady=6)
        self.tree.configure(yscrollcommand=scrollbar.set)

        severity_colors = {
            "critical": "#ff4d4d",
            "high": "#ff9f43",
            "medium": "#39c0ed",
            "low": "#57ffb0",
        }
        for severity, color in severity_colors.items():
            self.tree.tag_configure(severity, foreground=color)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        detail_frame = ttk.LabelFrame(findings_tab, text="Finding Details", style="Hacker.TLabelframe")
        detail_frame.pack(fill="x", padx=6, pady=(0, 6))

        self.detail_text = tk.Text(
            detail_frame,
            height=8,
            bg="#050f0b",
            fg="#57ffb0",
            insertbackground="#0aff9d",
            relief="flat",
            font=("Consolas", 11),
            wrap="word",
        )
        self.detail_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.detail_text.configure(state="disabled")

        metadata_container = ttk.Frame(metadata_tab, style="Hacker.TFrame")
        metadata_container.pack(fill="both", expand=True)

        self.metadata_tree = ttk.Treeview(
            metadata_container,
            columns=("category", "value"),
            show="headings",
            height=10,
            style="Hacker.Treeview",
        )
        self.metadata_tree.heading("category", text="Category")
        self.metadata_tree.heading("value", text="Path / Summary")
        self.metadata_tree.column("category", width=200)
        self.metadata_tree.column("value", width=680)
        self.metadata_tree.pack(fill="both", expand=True, side="left", padx=(0, 6), pady=(6, 6))

        meta_scrollbar = ttk.Scrollbar(metadata_container, orient="vertical", command=self.metadata_tree.yview)
        meta_scrollbar.pack(side="left", fill="y", pady=6)
        self.metadata_tree.configure(yscrollcommand=meta_scrollbar.set)

        extension_frame = ttk.LabelFrame(metadata_tab, text="Extension Summary", style="Hacker.TLabelframe")
        extension_frame.pack(fill="x", padx=6, pady=(0, 6))

        self.extension_tree = ttk.Treeview(
            extension_frame,
            columns=("extension", "count"),
            show="headings",
            height=6,
            style="Hacker.Treeview",
        )
        self.extension_tree.heading("extension", text="Extension")
        self.extension_tree.heading("count", text="Count")
        self.extension_tree.column("extension", width=200)
        self.extension_tree.column("count", width=120, anchor="center")
        self.extension_tree.pack(fill="x", padx=6, pady=(6, 6))

        self.metadata_summary_label = ttk.Label(metadata_tab, text="Metadata insights will appear here.")
        self.metadata_summary_label.pack(anchor="w", padx=12, pady=(0, 12))

    # endregion

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def _on_close(self) -> None:
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.root.destroy()

    def select_directory(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, directory)
            self.current_path = Path(directory)
            self._set_status(f"Target locked: {directory}")

    def trigger_scan(self) -> None:
        if self.scan_in_progress:
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
        self.tree.delete(*self.tree.get_children())
        self.metadata_tree.delete(*self.metadata_tree.get_children())
        self.extension_tree.delete(*self.extension_tree.get_children())
        self.tree_item_to_finding.clear()
        cache_template = {key: [] for key in self.metadata_cache.keys()}
        self.metadata_cache = cache_template
        self.progress_var.set(0)
        self.summary_label.config(text="Initializing deep scan...")
        self.metadata_summary_label.config(text="Metadata insights will appear here.")
        self._set_status("Initializing asynchronous scan...")
        self.scan_in_progress = True
        self.scan_start_time = time.time()
        self._update_timer()

        self.scan_task = self._submit_async(self._run_scan_async([path]))

    def _submit_async(self, coro: asyncio.Future) -> asyncio.Future:
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        future.add_done_callback(self._on_async_complete)
        return future

    def _on_async_complete(self, future: asyncio.Future) -> None:
        try:
            future.result()
        except Exception as exc:  # noqa: BLE001
            self.root.after(0, lambda: messagebox.showerror("Scan failed", str(exc)))
        finally:
            self.root.after(0, self._finalize_scan_state)

    def _finalize_scan_state(self) -> None:
        self.scan_in_progress = False
        if self.timer_job is not None:
            self.root.after_cancel(self.timer_job)
            self.timer_job = None
        if self.scan_start_time is not None:
            elapsed = int(time.time() - self.scan_start_time)
            minutes, seconds = divmod(elapsed, 60)
            self.timer_label.config(text=f"{minutes:02d}:{seconds:02d}")
        self.scan_start_time = None

    def _update_timer(self) -> None:
        if self.scan_start_time is None:
            return
        elapsed = int(time.time() - self.scan_start_time)
        minutes, seconds = divmod(elapsed, 60)
        self.timer_label.config(text=f"{minutes:02d}:{seconds:02d}")
        if self.scan_in_progress:
            self.timer_job = self.root.after(1000, self._update_timer)

    async def _run_scan_async(self, targets: list[Path]) -> None:
        total_targets = len(targets)
        for index, target in enumerate(targets, start=1):
            started = time.time()

            def file_progress(current: int, total: int, file_path: Optional[Path]) -> None:
                self.root.after(
                    0,
                    lambda: self._update_progress(
                        current,
                        total,
                        file_path,
                        index,
                        total_targets,
                        target,
                    ),
                )

            findings = await self.scanner.scan_directory_async(target, progress_callback=file_progress)
            metadata = self.scanner.collect_metadata(target)
            duration = time.time() - started
            self.root.after(
                0,
                lambda f=findings, m=metadata, d=duration, idx=index: self._display_results(f, m, target, d, idx, total_targets),
            )

        self.root.after(0, lambda: self._set_status("Batch complete" if total_targets > 1 else "Scan complete"))

    def _display_results(
        self,
        findings: list[Finding],
        metadata: dict[str, list[str]],
        target: Path,
        duration: float,
        position: int,
        total_targets: int,
    ) -> None:
        self.findings = findings
        self.metadata_cache = metadata
        self.last_scan_duration = duration
        self.tree_item_to_finding.clear()
        self._refresh_tree()
        self._update_metadata_view(metadata)

        summary = ScanSummary.from_findings(findings, duration=duration)

        file_metadata = []
        if metadata.get("filenames"):
            file_metadata.append(f"Sensitive names: {len(metadata['filenames'])}")
        if metadata.get("extensions"):
            file_metadata.append(f"Sensitive extensions: {len(metadata['extensions'])}")
        if metadata.get("env_files"):
            file_metadata.append(f"Env files: {len(metadata['env_files'])}")
        if metadata.get("large_files"):
            file_metadata.append(f"Large files: {len(metadata['large_files'])}")

        duration_text = f"{summary.duration:.1f}s"
        self.summary_label.config(
            text=(
                f"[{position}/{total_targets}] {target} | Findings: {summary.total_findings} | "
                f"Critical: {summary.critical} | High: {summary.high} | Medium: {summary.medium} | "
                f"Entropy hits: {summary.entropy_hits} | Duration: {duration_text}"
            )
        )

        meta_text = " | ".join(file_metadata) if file_metadata else "No sensitive files detected."
        self.metadata_summary_label.config(text=meta_text)

        if not findings:
            self._set_status("Scan complete - no indicators found.")
            self._set_detail_text("No findings to inspect.")
        else:
            self._set_status("Scan complete - review flagged entries.")
            first_item = next(iter(self.tree.get_children()), None)
            if first_item:
                self.tree.selection_set(first_item)
                self.tree.focus(first_item)

        if total_targets > 1:
            self.batch_status_label.config(
                text=f"Processed {position}/{total_targets} targets. Last: {target}",
            )

    def _refresh_tree(self) -> None:
        allowed_severity = {key for key, var in self.severity_vars.items() if var.get()}
        query = self.search_var.get().lower().strip()
        self.tree.delete(*self.tree.get_children())
        self.tree_item_to_finding.clear()

        for finding in self.findings:
            severity = finding.pattern.severity.lower()
            if severity not in allowed_severity:
                continue
            searchable = " ".join(
                [
                    finding.pattern.name.lower(),
                    str(finding.file_path).lower(),
                    finding.line.lower(),
                ]
            )
            if query and query not in searchable:
                continue
            snippet = finding.line.strip()
            if len(snippet) > 140:
                snippet = snippet[:137] + "..."
            item_id = self.tree.insert(
                "",
                "end",
                values=(
                    severity.upper(),
                    finding.pattern.name,
                    str(finding.file_path),
                    finding.line_number,
                    snippet,
                ),
                tags=(severity,),
            )
            self.tree_item_to_finding[item_id] = finding

        if not self.tree.get_children():
            self._set_detail_text("Filters returned no findings.")

    def _update_metadata_view(self, metadata: dict[str, list[str]]) -> None:
        self.metadata_tree.delete(*self.metadata_tree.get_children())
        self.extension_tree.delete(*self.extension_tree.get_children())

        for name in metadata.get("filenames", []):
            self.metadata_tree.insert("", "end", values=("Sensitive name", name))
        for name in metadata.get("env_files", []):
            self.metadata_tree.insert("", "end", values=("Environment file", name))
        for name in metadata.get("extensions", []):
            self.metadata_tree.insert("", "end", values=("Sensitive extension", name))
        for name in metadata.get("large_files", []):
            self.metadata_tree.insert("", "end", values=("Large file", name))

        for summary in metadata.get("extension_summary", []):
            if ":" in summary:
                extension, count = summary.split(":", 1)
                extension = extension.strip()
                count = count.strip()
            else:
                extension, count = summary, ""
            self.extension_tree.insert("", "end", values=(extension, count))

    def _set_detail_text(self, value: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, value)
        self.detail_text.configure(state="disabled")

    def _on_tree_select(self, _event: tk.Event[tk.Widget]) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        finding = self.tree_item_to_finding.get(selection[0])
        if not finding:
            return
        lines = [
            f"Pattern: {finding.pattern.name}",
            f"Severity: {finding.pattern.severity.upper()}",
            f"File: {finding.file_path}",
            f"Line: {finding.line_number}",
            f"Description: {finding.pattern.description}",
        ]
        if finding.entropy is not None:
            lines.append(f"Entropy score: {finding.entropy:.2f}")
        for key, value in finding.metadata.items():
            lines.append(f"{key.title()}: {value}")
        lines.append("\nSnippet:")
        lines.append(finding.line.strip())
        self._set_detail_text("\n".join(lines))

    def _update_progress(
        self,
        current: int,
        total: int,
        path: Optional[Path],
        index: int,
        total_targets: int,
        target: Path,
    ) -> None:
        progress = (current / total) * 100 if total else 0
        self.progress_var.set(progress)
        prefix = f"[{index}/{total_targets}] " if total_targets > 1 else ""
        if path is not None:
            display = str(path)[-90:]
            self._set_status(f"{prefix}Scanning {display}")
        else:
            self._set_status(f"{prefix}Scan complete for {target}")
            if total == 0:
                self.progress_var.set(100)

    def _set_status(self, text: str) -> None:
        self.status_label.config(text=text)

    def add_to_batch(self) -> None:
        path_value = self.path_entry.get().strip()
        if not path_value:
            messagebox.showwarning("Missing target", "Select a directory before adding to the batch.")
            return
        path = Path(path_value)
        if not path.exists() or not path.is_dir():
            messagebox.showerror("Invalid directory", "The selected path is not a directory.")
            return
        if path in self.batch_targets:
            messagebox.showinfo("Already queued", "The directory is already queued for batch scanning.")
            return
        self.batch_targets.append(path)
        self.batch_tree.insert("", "end", values=(str(path),))
        self.batch_status_label.config(text=f"{len(self.batch_targets)} target(s) queued.")

    def remove_from_batch(self) -> None:
        selection = self.batch_tree.selection()
        if not selection:
            return
        for item in selection:
            values = self.batch_tree.item(item).get("values", [])
            if values:
                path = Path(values[0])
                if path in self.batch_targets:
                    self.batch_targets.remove(path)
            self.batch_tree.delete(item)
        if self.batch_targets:
            self.batch_status_label.config(text=f"{len(self.batch_targets)} target(s) queued.")
        else:
            self.batch_status_label.config(text="No batch queued.")

    def clear_batch(self) -> None:
        self.batch_targets.clear()
        self.batch_tree.delete(*self.batch_tree.get_children())
        self.batch_status_label.config(text="No batch queued.")

    def run_batch(self) -> None:
        if self.scan_in_progress:
            messagebox.showinfo("Scan in progress", "Please wait for the current scan to complete.")
            return
        if not self.batch_targets:
            messagebox.showwarning("Empty batch", "Add directories to the batch queue first.")
            return
        self.scan_in_progress = True
        self.scan_start_time = time.time()
        self._update_timer()
        self.progress_var.set(0)
        self.summary_label.config(text="Starting batch operations...")
        self._set_status("Coordinating batch scan...")
        self.scan_task = self._submit_async(self._run_scan_async(list(self.batch_targets)))

    def _apply_options(self) -> None:
        self.scanner.include_hidden = self.include_hidden_var.get()
        self.scanner.enable_entropy = self.enable_entropy_var.get()
        self.scanner.max_workers = max(1, int(self.worker_count_var.get()))
        max_size_mb = max(1, int(self.max_file_size_var.get()))
        self.scanner.max_file_size = max_size_mb * 1024 * 1024
        extensions = [segment.strip().lower() for segment in self.extension_var.get().split(",") if segment.strip()]
        self.scanner.extensions = tuple(extensions) if extensions else None
        self._set_status(
            f"Options updated | workers={self.scanner.max_workers} | max size={max_size_mb}MB | entropy={'on' if self.scanner.enable_entropy else 'off'}"
        )

    def _reset_filters(self) -> None:
        for var in self.severity_vars.values():
            var.set(True)
        self.search_var.set("")
        self._refresh_tree()

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


def launch() -> None:
    root = tk.Tk()
    SecretScannerGUI(root)
    root.mainloop()


__all__ = ["SecretScannerGUI", "launch"]
