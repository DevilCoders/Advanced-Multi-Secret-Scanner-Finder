"""Predefined secret detection patterns and helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Pattern
import math
import re


@dataclass(frozen=True)
class SecretPattern:
    """Definition of a regex based pattern that may indicate a secret."""

    name: str
    pattern: Pattern[str]
    description: str
    severity: str = "medium"


@dataclass(frozen=True)
class HeuristicRule:
    """A heuristic rule that validates suspicious matches beyond pure regex."""

    name: str
    pattern: Pattern[str]
    description: str
    severity: str = "medium"
    minimum_length: int = 24
    entropy_threshold: float = 4.0

    def is_match(self, candidate: str) -> bool:
        """Return True when the candidate passes heuristic validation."""

        if len(candidate) < self.minimum_length:
            return False
        return shannon_entropy(candidate) >= self.entropy_threshold


def compile_patterns(patterns: Iterable[tuple[str, str, str, str]]) -> list[SecretPattern]:
    """Compile a list of pattern definitions into :class:`SecretPattern` objects."""

    compiled: list[SecretPattern] = []
    for name, regex, description, severity in patterns:
        compiled.append(
            SecretPattern(
                name=name,
                pattern=re.compile(regex, re.IGNORECASE | re.MULTILINE),
                description=description,
                severity=severity,
            )
        )
    return compiled


# Curated list of secret indicators. These cover common API keys, private keys,
# tokens, and credentials often found accidentally in repositories.
PATTERN_DEFINITIONS: tuple[tuple[str, str, str, str], ...] = (
    (
        "AWS Access Key",
        r"AKIA[0-9A-Z]{16}",
        "Potential AWS access key format.",
        "critical",
    ),
    (
        "AWS Secret Key",
        r'(?i)aws(.{0,20})?(secret|access)[\s:="\']{0,5}([A-Za-z0-9/+=]{40})',
        "Suspicious AWS secret access key assignment.",
        "critical",
    ),
    (
        "Google API Key",
        r"AIza[0-9A-Za-z\-_]{35}",
        "Google API key pattern.",
        "high",
    ),
    (
        "Slack Token",
        r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "Slack token format detected.",
        "high",
    ),
    (
        "GitHub Token",
        r"gh[pousr]_[A-Za-z0-9_]{36}",
        "GitHub personal access token format.",
        "high",
    ),
    (
        "Heroku API Key",
        r'(?i)heroku(.{0,20})?(api|key)[\s:="\']{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        "Heroku API key assignment detected.",
        "high",
    ),
    (
        "Private RSA Key",
        r"-----BEGIN RSA PRIVATE KEY-----",
        "RSA private key block.",
        "critical",
    ),
    (
        "Private EC Key",
        r"-----BEGIN EC PRIVATE KEY-----",
        "Elliptic curve private key block.",
        "critical",
    ),
    (
        "PEM Certificate",
        r"-----BEGIN CERTIFICATE-----",
        "Certificate file detected.",
        "medium",
    ),
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "Looks like a JSON Web Token (JWT).",
        "medium",
    ),
    (
        "Password Assignment",
        r'(?i)(password|passwd|pwd)[\s:="\']{1,6}[^\s"\']{4,}',
        "Hard-coded password assignment detected.",
        "high",
    ),
    (
        "Generic API Key",
        r'(?i)(api[_-]?key|token|secret)[\s:="\']{1,6}[A-Za-z0-9\-_/\.]{10,}',
        "Potential API key or secret token.",
        "medium",
    ),
    (
        "Database Connection String",
        r'(?i)(jdbc|mongodb|postgres|mysql|redis|amqp|dsn)://[^"\s]+',
        "Possible database connection string.",
        "medium",
    ),
    (
        "Username Password Pair",
        r'(?i)(username|user|login)[\s:="\']{1,6}[A-Za-z0-9._-]+[\s,;\n\r]{1,5}(password|passwd|pwd)[\s:="\']{1,6}[A-Za-z0-9!@#$%^&*()_+=-]{4,}',
        "Inline username/password combination.",
        "high",
    ),
    (
        "Basic Auth Header",
        r"Authorization: Basic [A-Za-z0-9+/=]{8,}",
        "HTTP Basic auth header with encoded credentials.",
        "medium",
    ),
    (
        "SSH Private Key",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "OpenSSH private key block.",
        "critical",
    ),
    (
        "Azure Connection String",
        r"Endpoint=sb://[A-Za-z0-9.-]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/=]{30,}",
        "Azure service bus connection string detected.",
        "high",
    ),
    (
        "Stripe API Key",
        r"sk_live_[0-9a-zA-Z]{24}",
        "Stripe live secret key.",
        "critical",
    ),
    (
        "Twilio API Key",
        r"SK[0-9a-fA-F]{32}",
        "Twilio API key.",
        "high",
    ),
    (
        "GitLab Personal Token",
        r"glpat-[0-9A-Za-z_-]{20,}",
        "GitLab personal access token.",
        "high",
    ),
    (
        "Azure Storage Key",
        r"(?i)(accountkey|azure_key|azure-storage-key)[\s:=\"]{0,5}[A-Za-z0-9+/=]{60,}",
        "Azure storage access key detected.",
        "critical",
    ),
    (
        "Firebase Web API Key",
        r"AIzaSy[0-9A-Za-z\-_]{33}",
        "Firebase web API key.",
        "medium",
    ),
    (
        "SendGrid API Key",
        r"SG\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{24}",
        "SendGrid API key pattern.",
        "high",
    ),
    (
        "Github OAuth Token",
        r"gho_[A-Za-z0-9]{36}",
        "GitHub OAuth token detected.",
        "high",
    ),
    (
        "Hashicorp Vault Token",
        r"hvs\.[A-Za-z0-9_-]{90,}",
        "Hashicorp Vault token.",
        "critical",
    ),
)

SECRET_PATTERNS: list[SecretPattern] = compile_patterns(PATTERN_DEFINITIONS)


SUSPICIOUS_FILENAMES: tuple[str, ...] = (
    "config.yaml",
    "config.yml",
    "config.json",
    "settings.py",
    "credentials.json",
    "credentials.yml",
    "secrets.json",
    "secrets.yml",
    "database.yml",
    "id_rsa",
    "id_dsa",
    "authorized_keys",
    "known_hosts",
)


SENSITIVE_EXTENSIONS: tuple[str, ...] = (
    ".pem",
    ".crt",
    ".cer",
    ".der",
    ".pfx",
    ".p12",
    ".key",
    ".ppk",
    ".jks",
    ".keystore",
)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for the provided string."""

    if not data:
        return 0.0
    frequency = {char: data.count(char) for char in set(data)}
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in frequency.values())


HEURISTIC_RULES: tuple[HeuristicRule, ...] = (
    HeuristicRule(
        name="High Entropy Token",
        pattern=re.compile(r"[A-Za-z0-9+/=]{32,}"),
        description="String with high entropy typical of randomly generated secrets.",
        severity="high",
        minimum_length=32,
        entropy_threshold=4.5,
    ),
    HeuristicRule(
        name="Hex Secret Blob",
        pattern=re.compile(r"0x?[0-9a-fA-F]{40,}"),
        description="Long hexadecimal sequence that may represent credentials or keys.",
        severity="medium",
        minimum_length=40,
        entropy_threshold=3.5,
    ),
    HeuristicRule(
        name="Base64 Credential",
        pattern=re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}={0,2}"),
        description="Base64-like token that could conceal credentials.",
        severity="medium",
        minimum_length=40,
        entropy_threshold=4.2,
    ),
)


__all__ = [
    "SecretPattern",
    "HeuristicRule",
    "SECRET_PATTERNS",
    "HEURISTIC_RULES",
    "SUSPICIOUS_FILENAMES",
    "SENSITIVE_EXTENSIONS",
    "shannon_entropy",
]

