"""Directory scanning logic for detecting potential secrets."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Callable, Iterator, Sequence
import json

from .scan_patterns import (
    HEURISTIC_RULES,
    SECRET_PATTERNS,
    SENSITIVE_EXTENSIONS,
    SUSPICIOUS_FILENAMES,
    HeuristicRule,
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
        enable_heuristics: bool = True,
        heuristic_rules: Sequence[HeuristicRule] | None = None,
    ) -> None:
        self.max_file_size = max_file_size
        self.include_hidden = include_hidden
        self.extensions = tuple(e.lower() for e in extensions) if extensions else None
        cpu_count = os.cpu_count() or 4
        self.max_workers = max_workers or min(32, max(4, cpu_count * 2))
        self.enable_heuristics = enable_heuristics
        self.heuristic_rules = tuple(heuristic_rules or HEURISTIC_RULES)
        self._heuristic_patterns = {
            rule: SecretPattern(
                name=rule.name,
                pattern=rule.pattern,
                description=rule.description,
                severity=rule.severity,
            )
            for rule in self.heuristic_rules
        }

    def _should_scan(self, path: Path) -> bool:
        if not self.include_hidden and any(part.startswith(".") for part in path.parts):
            return False
        try:
            if path.stat().st_size > self.max_file_size:
                return False
        except OSError:
            return False
        if self.extensions and path.suffix.lower() not in self.extensions:
            return False
        return True

    def _scan_file(self, path: Path) -> list[Finding]:
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
        findings.extend(self._run_regex_scans(text, path))
        if self.enable_heuristics:
            findings.extend(self._run_heuristics(text, path))
        return findings

    def _run_regex_scans(self, text: str, path: Path) -> list[Finding]:
        matches: list[Finding] = []
        for pattern in SECRET_PATTERNS:
            for match in pattern.pattern.finditer(text):
                matches.append(self._build_finding(pattern, path, text, match.start(), match.end()))
        return matches

    def _run_heuristics(self, text: str, path: Path) -> list[Finding]:
        heuristic_findings: list[Finding] = []
        for rule in self.heuristic_rules:
            for match in rule.pattern.finditer(text):
                candidate = match.group(0)
                if not rule.is_match(candidate):
                    continue
                heuristic_findings.append(
                    self._build_finding(
                        self._heuristic_patterns[rule],
                        path,
                        text,
                        match.start(),
                        match.end(),
                    )
                )
        return heuristic_findings

    @staticmethod
    def _build_finding(
        pattern: SecretPattern, path: Path, text: str, start: int, end: int
    ) -> Finding:
        line_number = text.count("\n", 0, start) + 1
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        if line_end == -1:
            line_end = len(text)
        line = text[line_start:line_end]
        return Finding(
            pattern=pattern,
            file_path=path,
            line_number=line_number,
            line=line,
        )

    def scan_directory(
        self,
        root: Path,
        *,
        progress_callback: Callable[[int, int, Path | None], None] | None = None,
    ) -> list[Finding]:
        if not root.exists():
            raise FileNotFoundError(f"Directory does not exist: {root}")

        all_files = [path for path in _iter_files(root) if self._should_scan(path)]
        total = len(all_files)
        findings: list[Finding] = []

        if not total:
            if progress_callback:
                progress_callback(0, 0, None)
            return findings

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(self._scan_file, path): path for path in all_files}
            for index, future in enumerate(as_completed(future_map), start=1):
                path = future_map[future]
                if progress_callback:
                    progress_callback(index, total, path)
                try:
                    findings.extend(future.result())
                except Exception:
                    continue

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
        progress_queue: asyncio.Queue[tuple[int, int, Path | None]] | None = None,
    ) -> list[Finding]:
        loop = asyncio.get_running_loop()

        def progress_adapter(current: int, total: int, path: Path | None) -> None:
            if not progress_queue:
                return
            loop.call_soon_threadsafe(progress_queue.put_nowait, (current, total, path))

        return await asyncio.to_thread(
            self.scan_directory, root, progress_callback=progress_adapter if progress_queue else None
        )

    def scan_batch(
        self,
        roots: Sequence[Path],
        *,
        file_progress_callback: Callable[[Path, int, int, Path | None], None] | None = None,
        job_progress_callback: Callable[[int, int, Path], None] | None = None,
    ) -> dict[Path, list[Finding]]:
        if not roots:
            return {}

        results: dict[Path, list[Finding]] = {}
        total_jobs = len(roots)

        def make_file_callback(root: Path) -> Callable[[int, int, Path | None], None] | None:
            if file_progress_callback is None:
                return None

            def callback(current: int, total: int, path: Path | None) -> None:
                file_progress_callback(root, current, total, path)

            return callback

        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, total_jobs))) as executor:
            future_map = {}
            for root in roots:
                callback = make_file_callback(root)
                future_map[executor.submit(self.scan_directory, root, progress_callback=callback)] = root

            for index, future in enumerate(as_completed(future_map), start=1):
                root = future_map[future]
                try:
                    results[root] = future.result()
                except Exception:
                    results[root] = []
                if job_progress_callback:
                    job_progress_callback(index, total_jobs, root)

        return results

    async def scan_batch_async(
        self,
        roots: Sequence[Path],
        *,
        file_progress_callback: Callable[[Path, int, int, Path | None], None] | None = None,
        job_progress_callback: Callable[[int, int, Path], None] | None = None,
        max_concurrent: int | None = None,
    ) -> dict[Path, list[Finding]]:
        if not roots:
            return {}

        semaphore = asyncio.Semaphore(max_concurrent or min(self.max_workers, len(roots)))
        results: dict[Path, list[Finding]] = {}
        total_jobs = len(roots)

        async def run_job(index: int, root: Path) -> None:
            async with semaphore:
                queue: asyncio.Queue[tuple[int, int, Path | None]] | None = None
                relay_task: asyncio.Task[None] | None = None
                if file_progress_callback:
                    queue = asyncio.Queue()

                    async def relay() -> None:
                        while True:
                            current, total, path_item = await queue.get()
                            file_progress_callback(root, current, total, path_item)
                            if path_item is None and current == total:
                                break

                    relay_task = asyncio.create_task(relay())

                findings = await self.scan_directory_async(root, progress_queue=queue)
                results[root] = findings

                if relay_task is not None:
                    await relay_task
                if job_progress_callback:
                    job_progress_callback(index, total_jobs, root)

        await asyncio.gather(*(run_job(i, root) for i, root in enumerate(roots, start=1)))
        return results

    @staticmethod
    def collect_metadata(path: Path) -> dict[str, list[str]]:
        """Return metadata of suspicious files and extensions present."""

        filenames: list[str] = []
        extensions: list[str] = []

        for file in _iter_files(path):
            name = file.name.lower()
            suffix = file.suffix.lower()
            if name in SUSPICIOUS_FILENAMES:
                filenames.append(str(file))
            if suffix in SENSITIVE_EXTENSIONS:
                extensions.append(str(file))
        return {"filenames": filenames, "extensions": extensions}

    @staticmethod
    def export_findings(findings: Sequence[Finding], output_path: Path) -> None:
        data = [finding.to_dict() for finding in findings]
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


__all__ = ["SecretScanner", "Finding"]
