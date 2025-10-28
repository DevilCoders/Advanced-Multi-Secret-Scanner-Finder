"""Directory scanning logic for detecting potential secrets."""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence
import asyncio
import io
import json
import math
import os
import re
import threading
import time

from .scan_patterns import (
    SECRET_PATTERNS,
    SENSITIVE_DIRECTORIES,
    SENSITIVE_EXTENSIONS,
    SUSPICIOUS_FILENAMES,
    SecretPattern,
)


@dataclass
class Finding:
    """Representation of a potential secret occurrence."""

    pattern: SecretPattern
    file_path: Path
    line_number: int
    line: str
    context: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.pattern.name,
            "description": self.pattern.description,
            "severity": self.pattern.severity,
            "file": str(self.file_path),
            "line_number": str(self.line_number),
            "line": self.line.strip(),
            "context": self.context.strip(),
        }


@dataclass
class ScanStats:
    """Summary of operational statistics from a scan."""

    total_files: int
    scanned_files: int
    skipped_files: int
    duration: float


@dataclass
class BatchScanResult:
    """Result metadata for a batch job run."""

    path: Path
    findings: list[Finding]
    metadata: dict[str, list[str]]
    stats: ScanStats


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            yield path


class SecretScanner:
    """Scan directories for files containing potential secrets."""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def __init__(
        self,
        *,
        max_file_size: int | None = None,
        include_hidden: bool = False,
        extensions: Sequence[str] | None = None,
        max_workers: int | None = None,
        enable_entropy_checks: bool = True,
        entropy_threshold: float = 4.0,
    ) -> None:
        self.max_file_size = max_file_size
        self.include_hidden = include_hidden
        self.extensions = tuple(e.lower() for e in extensions) if extensions else None
        self.max_workers = max_workers or max(4, (os_cpu_count() or 4) * 2)
        self.enable_entropy_checks = enable_entropy_checks
        self.entropy_threshold = entropy_threshold
        self._last_stats: ScanStats | None = None
        self._last_scan_cancelled = False

    def clone(self) -> "SecretScanner":
        return SecretScanner(
            max_file_size=self.max_file_size,
            include_hidden=self.include_hidden,
            extensions=self.extensions,
            max_workers=self.max_workers,
            enable_entropy_checks=self.enable_entropy_checks,
            entropy_threshold=self.entropy_threshold,
        )

    def update_settings(
        self,
        *,
        include_hidden: bool | None = None,
        max_file_size: int | None = None,
        extensions: Sequence[str] | None = None,
        max_workers: int | None = None,
        enable_entropy_checks: bool | None = None,
        entropy_threshold: float | None = None,
    ) -> None:
        if include_hidden is not None:
            self.include_hidden = include_hidden
        if max_file_size is not None:
            self.max_file_size = max_file_size if max_file_size > 0 else None
        if extensions is not None:
            cleaned = tuple(sorted({e.lower().strip() for e in extensions if e.strip()}))
            self.extensions = cleaned or None
        if max_workers is not None and max_workers > 0:
            self.max_workers = max_workers
        if enable_entropy_checks is not None:
            self.enable_entropy_checks = enable_entropy_checks
        if entropy_threshold is not None and entropy_threshold > 0:
            self.entropy_threshold = entropy_threshold

    @property
    def last_stats(self) -> ScanStats | None:
        return self._last_stats

    @property
    def last_scan_cancelled(self) -> bool:
        return self._last_scan_cancelled

    def _should_scan(self, path: Path) -> bool:
        if not self.include_hidden and any(part.startswith(".") for part in path.parts):
            return False
        if self.max_file_size is not None:
            try:
                if path.stat().st_size > self.max_file_size:
                    return False
            except OSError:
                return False
        if self.extensions and path.suffix.lower() not in self.extensions:
            return False
        return True

    def _scan_file(
        self, path: Path, *, cancel_event: threading.Event | None = None
    ) -> Iterable[Finding]:
        if cancel_event and cancel_event.is_set():
            return []

        try:
            with path.open("rb") as file:
                sample = file.read(4096)
                if _is_binary(sample):
                    return []
                file.seek(0)
                text_stream = io.TextIOWrapper(file, encoding="utf-8", errors="ignore")

                findings: list[Finding] = []
                prev_lines: deque[str] = deque(maxlen=2)
                line_number = 1
                current_line = text_stream.readline()

                while current_line:
                    if cancel_event and cancel_event.is_set():
                        break

                    next_line = text_stream.readline()
                    stripped_line = current_line.rstrip("\n")

                    for pattern in SECRET_PATTERNS:
                        for match in pattern.pattern.finditer(stripped_line):
                            context = self._compose_context(
                                prev_lines,
                                stripped_line,
                                match.start(),
                                match.end(),
                                next_line,
                            )
                            findings.append(
                                Finding(
                                    pattern=pattern,
                                    file_path=path,
                                    line_number=line_number,
                                    line=stripped_line,
                                    context=context,
                                )
                            )

                    if self.enable_entropy_checks:
                        findings.extend(
                            self._run_entropy_checks(
                                stripped_line,
                                path,
                                line_number,
                                prev_lines,
                                next_line,
                            )
                        )
                        findings.extend(
                            self._keyword_sweeps(
                                stripped_line,
                                path,
                                line_number,
                                prev_lines,
                                next_line,
                            )
                        )

                    prev_lines.append(current_line)
                    current_line = next_line
                    line_number += 1

        except (OSError, UnicodeDecodeError):
            return []

        return findings

    @staticmethod
    def _extract_context(text: str, start: int, end: int, radius: int = 120) -> str:
        snippet_start = max(0, start - radius)
        snippet_end = min(len(text), end + radius)
        snippet = text[snippet_start:snippet_end]
        return snippet.strip()

    def _run_entropy_checks(
        self,
        line: str,
        path: Path,
        line_number: int,
        prev_lines: deque[str],
        next_line: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _ENTROPY_REGEX.finditer(line):
            candidate = match.group(0)
            entropy = _shannon_entropy(candidate)
            if entropy < self.entropy_threshold:
                continue
            severity = "high" if len(candidate) > 32 else "medium"
            pattern = HIGH_ENTROPY_PATTERN_HIGH if severity == "high" else HIGH_ENTROPY_PATTERN_MEDIUM
            context = self._compose_context(
                prev_lines,
                line,
                match.start(),
                match.end(),
                next_line,
            )
            findings.append(
                Finding(
                    pattern=pattern,
                    file_path=path,
                    line_number=line_number,
                    line=line,
                    context=context,
                )
            )
        return findings

    def _keyword_sweeps(
        self,
        line: str,
        path: Path,
        line_number: int,
        prev_lines: deque[str],
        next_line: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _CREDENTIAL_KEYWORD_REGEX.finditer(line):
            context = self._compose_context(
                prev_lines,
                line,
                match.start(),
                match.end(),
                next_line,
            )
            findings.append(
                Finding(
                    pattern=GENERIC_KEYWORD_PATTERN,
                    file_path=path,
                    line_number=line_number,
                    line=line,
                    context=context,
                )
            )
        return findings

    @staticmethod
    def _compose_context(
        prev_lines: deque[str],
        current_line: str,
        match_start: int,
        match_end: int,
        next_line: str | None,
        *,
        radius: int = 120,
    ) -> str:
        context_parts: list[str] = []
        for line in list(prev_lines)[-2:]:
            stripped = line.strip()
            if stripped:
                context_parts.append(stripped)

        snippet_start = max(0, match_start - radius)
        snippet_end = min(len(current_line), match_end + radius)
        snippet = current_line[snippet_start:snippet_end].strip()
        if snippet:
            context_parts.append(snippet)

        if next_line:
            stripped_next = next_line.strip()
            if stripped_next:
                context_parts.append(stripped_next)

        return "\n".join(context_parts).strip()

    def _scan_worker(
        self,
        path: Path,
        *,
        cancel_event: threading.Event | None = None,
    ) -> tuple[Path, list[Finding]]:
        return path, list(self._scan_file(path, cancel_event=cancel_event))

    def scan_directory(
        self,
        root: Path,
        *,
        progress_callback: Callable[[int, int, Path | None], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[Finding]:
        if not root.exists():
            raise FileNotFoundError(f"Directory does not exist: {root}")

        start_time = time.perf_counter()
        all_files = list(_iter_files(root))
        eligible_files = [path for path in all_files if self._should_scan(path)]
        filtered_out = len(all_files) - len(eligible_files)
        total = len(eligible_files)
        findings: list[Finding] = []

        if cancel_event and cancel_event.is_set():
            self._last_stats = ScanStats(
                total_files=len(all_files),
                scanned_files=0,
                skipped_files=len(all_files),
                duration=time.perf_counter() - start_time,
            )
            self._last_scan_cancelled = True
            if progress_callback:
                progress_callback(0, total, None)
            return []

        processed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_worker, path, cancel_event=cancel_event): path
                for path in eligible_files
            }
            for future in as_completed(futures):
                path, result = future.result()
                processed += 1
                findings.extend(result)
                if progress_callback:
                    progress_callback(processed, total, path)
                if cancel_event and cancel_event.is_set():
                    break

        if progress_callback:
            progress_callback(processed, total, None)

        findings.sort(
            key=lambda f: (
                self.SEVERITY_ORDER.get(f.pattern.severity, 99),
                str(f.file_path),
                f.line_number,
            )
        )

        duration = time.perf_counter() - start_time
        skipped_files = filtered_out + (total - processed)
        self._last_stats = ScanStats(
            total_files=len(all_files),
            scanned_files=processed,
            skipped_files=skipped_files,
            duration=duration,
        )
        self._last_scan_cancelled = bool(cancel_event and cancel_event.is_set())

        return findings

    async def async_scan_directory(
        self,
        root: Path,
        *,
        progress_callback: Callable[[int, int, Path | None], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[Finding]:
        loop = asyncio.get_running_loop()
        func = partial(
            self.scan_directory,
            root,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
        return await loop.run_in_executor(None, func)

    def scan_specific_file(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise FileNotFoundError(path)
        if not self._should_scan(path):
            return []
        return list(self._scan_file(path))

    def batch_scan(
        self,
        roots: Sequence[Path],
        *,
        parallel_jobs: int | None = None,
        progress_callback: Callable[[Path, int, int], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[BatchScanResult]:
        jobs = [path for path in roots if path.exists() and path.is_dir()]
        if not jobs:
            return []

        max_workers = parallel_jobs or min(len(jobs), self.max_workers)
        results: list[BatchScanResult] = []

        def run_job(path: Path) -> BatchScanResult:
            if cancel_event and cancel_event.is_set():
                empty_stats = ScanStats(total_files=0, scanned_files=0, skipped_files=0, duration=0.0)
                return BatchScanResult(path=path, findings=[], metadata={}, stats=empty_stats)
            clone = self.clone()

            def job_progress(current: int, total: int, _path: Path | None) -> None:
                if progress_callback and total:
                    progress_callback(path, current, total)

            findings = clone.scan_directory(
                path,
                progress_callback=job_progress,
                cancel_event=cancel_event,
            )
            metadata = clone.collect_metadata(path)
            stats = clone.last_stats or ScanStats(0, 0, 0, 0.0)
            return BatchScanResult(path=path, findings=findings, metadata=metadata, stats=stats)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {executor.submit(run_job, path): path for path in jobs}
            for future in as_completed(future_to_path):
                results.append(future.result())
                if cancel_event and cancel_event.is_set():
                    break

            if cancel_event and cancel_event.is_set():
                for future in future_to_path:
                    future.cancel()

        results.sort(key=lambda item: str(item.path))
        return results

    async def async_batch_scan(
        self,
        roots: Sequence[Path],
        *,
        parallel_jobs: int | None = None,
        progress_callback: Callable[[Path, int, int], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[BatchScanResult]:
        loop = asyncio.get_running_loop()
        func = partial(
            self.batch_scan,
            roots,
            parallel_jobs=parallel_jobs,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )
        return await loop.run_in_executor(None, func)

    @staticmethod
    def collect_metadata(path: Path) -> dict[str, list[str]]:
        """Return metadata of suspicious files and extensions present."""

        filenames: list[str] = []
        extensions: list[str] = []
        directories: list[str] = []

        for file in _iter_files(path):
            name = file.name.lower()
            suffix = file.suffix.lower()
            if name in SUSPICIOUS_FILENAMES:
                filenames.append(str(file))
            if suffix in SENSITIVE_EXTENSIONS:
                extensions.append(str(file))
            if any(part.lower() in SENSITIVE_DIRECTORIES for part in file.parts):
                directories.append(str(file.parent))
        return {
            "filenames": sorted(set(filenames)),
            "extensions": sorted(set(extensions)),
            "directories": sorted(set(directories)),
        }

    @staticmethod
    def export_findings(findings: Sequence[Finding], output_path: Path) -> None:
        data = [finding.to_dict() for finding in findings]
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def os_cpu_count() -> int | None:
    try:
        return os.cpu_count()  # type: ignore[attr-defined]
    except AttributeError:
        return None


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    frequency = {char: data.count(char) for char in set(data)}
    length = len(data)
    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


_ENTROPY_REGEX = re.compile(r"[A-Za-z0-9+/=]{20,}")

HIGH_ENTROPY_PATTERN_HIGH = SecretPattern(
    name="High Entropy Secret",
    pattern=_ENTROPY_REGEX,
    description="High-entropy string detected; likely credential.",
    severity="high",
)

HIGH_ENTROPY_PATTERN_MEDIUM = SecretPattern(
    name="Suspicious Token",
    pattern=_ENTROPY_REGEX,
    description="Possible encoded credential detected via entropy heuristic.",
    severity="medium",
)

_CREDENTIAL_KEYWORD_REGEX = re.compile(
    r"(?i)(secret|token|session|credential|apikey)[^\n]{0,8}[=:][^\n]{8,}"
)

GENERIC_KEYWORD_PATTERN = SecretPattern(
    name="Credential Keyword",
    pattern=_CREDENTIAL_KEYWORD_REGEX,
    description="Keyword-based heuristic secret detection.",
    severity="medium",
)


__all__ = [
    "BatchScanResult",
    "Finding",
    "ScanStats",
    "SecretScanner",
]
