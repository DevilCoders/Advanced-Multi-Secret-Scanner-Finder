"""Directory scanning logic for detecting potential secrets."""
from __future__ import annotations

import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import partial
import json
import os
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence
import time

from .scan_patterns import (
    SECRET_PATTERNS,
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

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.pattern.name,
            "description": self.pattern.description,
            "severity": self.pattern.severity,
            "file": str(self.file_path),
            "line_number": str(self.line_number),
            "line": self.line.strip(),
        }


@dataclass
class BatchResult:
    """Summary of a batch scan over a single target directory."""

    root: Path
    findings: list[Finding]
    metadata: dict[str, list[str] | dict[str, int]]
    duration_s: float

    def severity_breakdown(self) -> Counter[str]:
        counter: Counter[str] = Counter()
        for finding in self.findings:
            counter[finding.pattern.severity] += 1
        return counter


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            yield path


class SecretScanner:
    """Scan directories for files containing potential secrets."""

    def __init__(
        self,
        *,
        max_file_size: int = 4 * 1024 * 1024,
        include_hidden: bool = False,
        extensions: Sequence[str] | None = None,
        max_workers: int | None = None,
    ) -> None:
        self.max_file_size = max_file_size
        self.include_hidden = include_hidden
        self.extensions = tuple(e.lower() for e in extensions) if extensions else None
        cpu_count = os.cpu_count() or 4
        self.max_workers = max_workers or max(4, cpu_count * 2)

    def _should_scan(self, path: Path) -> bool:
        if not self.include_hidden and any(part.startswith(".") for part in path.parts):
            return False
        try:
            size = path.stat().st_size
        except OSError:
            return False
        if size > self.max_file_size:
            return False
        if self.extensions and path.suffix.lower() not in self.extensions:
            return False
        return True

    def _scan_file(self, path: Path) -> Iterable[Finding]:
        try:
            with path.open("rb") as file:
                sample = file.read(2048)
                if _is_binary(sample):
                    return []
                file.seek(0)
                text = file.read().decode("utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return []

        findings: list[Finding] = []
        for pattern in SECRET_PATTERNS:
            for match in pattern.pattern.finditer(text):
                if not pattern.is_valid(match, text):
                    continue
                line_number = text.count("\n", 0, match.start()) + 1
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                line = text[line_start:line_end]
                findings.append(
                    Finding(
                        pattern=pattern,
                        file_path=path,
                        line_number=line_number,
                        line=line,
                    )
                )
        return findings

    def scan_directory(
        self,
        root: Path,
        *,
        progress_callback: Callable[[int, int, Path | None], None] | None = None,
        workers: int | None = None,
    ) -> list[Finding]:
        if not root.exists():
            raise FileNotFoundError(f"Directory does not exist: {root}")

        candidate_files = [path for path in _iter_files(root) if self._should_scan(path)]
        total = len(candidate_files)
        findings: list[Finding] = []

        if total == 0:
            if progress_callback:
                progress_callback(0, 0, None)
            return findings

        max_workers = workers or self.max_workers
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(self._scan_file, path): path for path in candidate_files
            }

            completed = 0
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                except Exception:
                    result = []
                findings.extend(result)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total, path)

        if progress_callback:
            progress_callback(total, total, None)
        findings.sort(key=lambda f: (f.pattern.severity, str(f.file_path), f.line_number))
        return findings

    def scan_specific_file(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise FileNotFoundError(path)
        if not self._should_scan(path):
            return []
        return list(self._scan_file(path))

    async def scan_directory_async(
        self,
        root: Path,
        *,
        progress_callback: Callable[[int, int, Path | None], None] | None = None,
        workers: int | None = None,
    ) -> list[Finding]:
        loop = asyncio.get_running_loop()
        func = partial(self.scan_directory, root, progress_callback=progress_callback, workers=workers)
        return await loop.run_in_executor(None, func)

    async def scan_batch_async(
        self,
        roots: Sequence[Path | str],
        *,
        per_directory_callback: Callable[[Path, int, int, Path | None], None] | None = None,
        batch_progress_callback: Callable[[int, int, Path], None] | None = None,
        workers: int | None = None,
    ) -> list[BatchResult]:
        async def run_single(root_path: Path) -> BatchResult:
            start = time.perf_counter()

            def wrapped_progress(current: int, total: int, path: Path | None) -> None:
                if per_directory_callback:
                    per_directory_callback(root_path, current, total, path)

            findings = await self.scan_directory_async(
                root_path,
                progress_callback=wrapped_progress if per_directory_callback else None,
                workers=workers,
            )
            metadata = self.collect_metadata(root_path)
            duration = time.perf_counter() - start
            return BatchResult(root=root_path, findings=findings, metadata=metadata, duration_s=duration)

        tasks = [asyncio.create_task(run_single(Path(root))) for root in roots]

        results: list[BatchResult] = []
        completed = 0
        total = len(tasks)
        for task in asyncio.as_completed(tasks):
            result = await task
            results.append(result)
            completed += 1
            if batch_progress_callback:
                batch_progress_callback(completed, total, result.root)

        results.sort(key=lambda r: str(r.root))
        return results

    @staticmethod
    def collect_metadata(path: Path, *, limit: int = 10) -> dict[str, list[str] | dict[str, int]]:
        """Return metadata of suspicious files, extensions and aggregate counts."""

        filenames: list[str] = []
        extensions: list[str] = []
        extension_counts: Counter[str] = Counter()

        for file in _iter_files(path):
            name = file.name.lower()
            suffix = file.suffix.lower()
            if name in SUSPICIOUS_FILENAMES:
                filenames.append(str(file))
            if suffix in SENSITIVE_EXTENSIONS:
                extensions.append(str(file))
                extension_counts[suffix] += 1

        return {
            "filenames": filenames,
            "extensions": extensions,
            "extension_counts": dict(extension_counts.most_common(limit)),
        }

    @staticmethod
    def compute_telemetry(findings: Sequence[Finding]) -> dict[str, object]:
        """Return severity counts, top patterns and a weighted risk score."""

        severity_counts: Counter[str] = Counter()
        pattern_counts: Counter[str] = Counter()
        risk_weights = {"critical": 5, "high": 3, "medium": 2, "low": 1}
        risk_score = 0

        for finding in findings:
            severity = finding.pattern.severity
            severity_counts[severity] += 1
            pattern_counts[finding.pattern.name] += 1
            risk_score += risk_weights.get(severity, 1)

        return {
            "severity": dict(severity_counts),
            "top_patterns": pattern_counts.most_common(8),
            "risk_score": risk_score,
        }

    @staticmethod
    def export_findings(findings: Sequence[Finding], output_path: Path) -> None:
        data = [finding.to_dict() for finding in findings]
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
