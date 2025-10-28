"""Directory scanning logic for detecting potential secrets."""
from __future__ import annotations

import asyncio
import json
import math
import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

from .scan_patterns import (
    ENTROPY_CANDIDATE_REGEX,
    ENV_FILE_HINTS,
    HIGH_ENTROPY_PATTERN,
    SECRET_PATTERNS,
    SENSITIVE_EXTENSIONS,
    SUSPICIOUS_FILENAMES,
    SecretPattern,
)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    """Representation of a potential secret occurrence."""

    pattern: SecretPattern
    file_path: Path
    line_number: int
    line: str
    entropy: float | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, str]:
        base = {
            "name": self.pattern.name,
            "description": self.pattern.description,
            "severity": self.pattern.severity,
            "file": str(self.file_path),
            "line_number": str(self.line_number),
            "line": self.line.strip(),
        }
        if self.entropy is not None:
            base["entropy"] = f"{self.entropy:.2f}"
        base.update(self.metadata)
        return base


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def _iter_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    if not length:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


class SecretScanner:
    """Scan directories for files containing potential secrets."""

    def __init__(
        self,
        *,
        max_file_size: int = 4 * 1024 * 1024,
        include_hidden: bool = False,
        extensions: Sequence[str] | None = None,
        max_workers: int | None = None,
        enable_entropy: bool = True,
        entropy_threshold: float = 4.0,
    ) -> None:
        self.max_file_size = max_file_size
        self.include_hidden = include_hidden
        self.extensions = tuple(e.lower() for e in extensions) if extensions else None
        workers = max_workers if max_workers and max_workers > 0 else (os.cpu_count() or 4)
        self.max_workers = max(1, workers)
        self.enable_entropy = enable_entropy
        self.entropy_threshold = entropy_threshold

    def _should_scan(self, path: Path) -> bool:
        if not self.include_hidden and any(part.startswith(".") for part in path.parts):
            return False
        if path.stat().st_size > self.max_file_size:
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

        if self.enable_entropy:
            findings.extend(self._scan_high_entropy(text, path))

        return findings

    def _scan_high_entropy(self, text: str, path: Path) -> Iterable[Finding]:
        findings: list[Finding] = []
        for match in ENTROPY_CANDIDATE_REGEX.finditer(text):
            candidate = match.group(0)
            if len(candidate) > 256:
                continue
            entropy = _shannon_entropy(candidate)
            if entropy < self.entropy_threshold:
                continue
            line_number = text.count("\n", 0, match.start()) + 1
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            findings.append(
                Finding(
                    pattern=HIGH_ENTROPY_PATTERN,
                    file_path=path,
                    line_number=line_number,
                    line=line,
                    entropy=entropy,
                    metadata={
                        "preview": candidate[:16] + "..." if len(candidate) > 16 else candidate
                    },
                )
            )
        return findings

    def scan_directory(
        self,
        root: Path,
        *,
        progress_callback: Callable[[int, int, Path | None], None] | None = None,
    ) -> list[Finding]:
        if not root.exists():
            raise FileNotFoundError(f"Directory does not exist: {root}")

        all_files = list(_iter_files(root))
        total = len(all_files)
        findings: list[Finding] = []

        def scan_path(path: Path) -> list[Finding]:
            if not self._should_scan(path):
                return []
            return list(self._scan_file(path))

        progress_index = 0
        if total == 0 and progress_callback:
            progress_callback(0, 0, None)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for path, result in zip(all_files, executor.map(scan_path, all_files)):
                findings.extend(result)
                progress_index += 1
                if progress_callback:
                    progress_callback(progress_index, total, path)

        if progress_callback and total:
            progress_callback(total, total, None)

        findings.sort(
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.pattern.severity, 99),
                str(finding.file_path),
                finding.line_number,
            )
        )
        return findings

    async def scan_directory_async(
        self,
        root: Path,
        *,
        progress_callback: Callable[[int, int, Path | None], None] | None = None,
    ) -> list[Finding]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.scan_directory(root, progress_callback=progress_callback),
        )

    async def scan_batch_async(
        self,
        roots: Sequence[Path],
        *,
        progress_callback: Callable[[Path, int, int, Path | None], None] | None = None,
    ) -> dict[Path, list[Finding]]:
        results: dict[Path, list[Finding]] = {}
        for root in roots:
            inner_callback = partial(progress_callback, root) if progress_callback else None
            findings = await self.scan_directory_async(root, progress_callback=inner_callback)
            results[root] = findings
        return results

    def scan_specific_file(self, path: Path) -> list[Finding]:
        if not path.exists():
            raise FileNotFoundError(path)
        if not self._should_scan(path):
            return []
        return list(self._scan_file(path))

    @staticmethod
    def collect_metadata(path: Path) -> dict[str, list[str]]:
        """Return metadata of suspicious files and extensions present."""

        filenames: list[str] = []
        extensions: list[str] = []
        env_files: list[str] = []
        oversized_files: list[str] = []
        extension_counts: Counter[str] = Counter()

        for file in _iter_files(path):
            name = file.name.lower()
            suffix = file.suffix.lower()
            if name in SUSPICIOUS_FILENAMES:
                filenames.append(str(file))
            if suffix in SENSITIVE_EXTENSIONS:
                extensions.append(str(file))
            if name in ENV_FILE_HINTS:
                env_files.append(str(file))
            if suffix:
                extension_counts[suffix] += 1
            try:
                size = file.stat().st_size
            except OSError:
                continue
            if size > 10 * 1024 * 1024:
                oversized_files.append(f"{file} ({size // 1024} KB)")

        extension_summary = [f"{ext}: {count}" for ext, count in extension_counts.most_common(10)]

        return {
            "filenames": filenames,
            "extensions": extensions,
            "env_files": env_files,
            "large_files": oversized_files,
            "extension_summary": extension_summary,
        }

    @staticmethod
    def export_findings(findings: Sequence[Finding], output_path: Path) -> None:
        data = [finding.to_dict() for finding in findings]
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
