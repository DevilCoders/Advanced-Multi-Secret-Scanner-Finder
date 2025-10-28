"""Predefined secret detection patterns and helpers."""
from __future__ import annotations

from dataclasses import dataclass
from math import log2
from typing import Callable, Iterable, Match, Pattern
import re


@dataclass(frozen=True)
class SecretPattern:
    """Definition of a pattern that may indicate a secret."""

    name: str
    pattern: Pattern[str]
    description: str
    severity: str = "medium"
    validator: Callable[[Match[str], str], bool] | None = None

    def is_valid(self, match: Match[str], text: str) -> bool:
        """Return whether the regex match should be treated as a real finding."""

        if not self.validator:
            return True
        return self.validator(match, text)


PatternDefinition = tuple[str, str, str, str] | tuple[
    str,
    str,
    str,
    str,
    Callable[[Match[str], str], bool],
]


def compile_patterns(patterns: Iterable[PatternDefinition]) -> list[SecretPattern]:
    """Compile a list of pattern definitions into :class:`SecretPattern` objects."""

    compiled: list[SecretPattern] = []
    for definition in patterns:
        if len(definition) == 4:
            name, regex, description, severity = definition
            validator = None
        else:
            name, regex, description, severity, validator = definition
        compiled.append(
            SecretPattern(
                name=name,
                pattern=re.compile(regex, re.IGNORECASE | re.MULTILINE),
                description=description,
                severity=severity,
                validator=validator,
            )
        )
    return compiled


def _shannon_entropy(data: str) -> float:
    alphabet = set(data)
    if not data or len(alphabet) == 1:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in alphabet:
        probability = data.count(char) / length
        entropy -= probability * log2(probability)
    return entropy


def _high_entropy_validator(match: Match[str], _: str, *, threshold: float = 4.0) -> bool:
    return _shannon_entropy(match.group(0)) >= threshold


def _private_key_block_validator(match: Match[str], text: str) -> bool:
    """Avoid false positives by ensuring matching block contains proper footer."""

    block = match.group(0)
    if "PRIVATE KEY" not in block.upper():
        return False
    # Ensure corresponding END marker exists in proximity.
    closing = block.replace("BEGIN", "END")
    return closing in text


# Curated list of secret indicators. These cover common API keys, private keys,
# tokens, and credentials often found accidentally in repositories.
PATTERN_DEFINITIONS: tuple[PatternDefinition, ...] = (
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
        r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
        "RSA private key block.",
        "critical",
        _private_key_block_validator,
    ),
    (
        "Private EC Key",
        r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
        "Elliptic curve private key block.",
        "critical",
        _private_key_block_validator,
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
        "Azure Storage Account Key",
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,};",
        "Azure storage account connection string detected.",
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
        "OpenAI API Key",
        r"sk-[A-Za-z0-9]{48}",
        "OpenAI API key pattern.",
        "high",
    ),
    (
        "GitLab Personal Token",
        r"glpat-[0-9a-zA-Z_-]{20,}",
        "GitLab personal access token format.",
        "high",
    ),
    (
        "Azure DevOps Personal Token",
        r"azd[a-z0-9]{52}",
        "Azure DevOps personal access token.",
        "high",
    ),
    (
        "DigitalOcean Access Token",
        r"do-[0-9a-f]{64}",
        "DigitalOcean access token.",
        "high",
    ),
    (
        "SendGrid API Key",
        r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "SendGrid API key detected.",
        "high",
    ),
    (
        "Discord Bot Token",
        r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
        "Discord bot token structure detected.",
        "medium",
    ),
    (
        "Mailchimp API Key",
        r"[0-9a-f]{32}-us\d{1,2}",
        "Mailchimp API key.",
        "medium",
    ),
    (
        "Firebase Cloud Messaging Key",
        r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "Firebase server key detected.",
        "high",
    ),
    (
        "NPM Token",
        r"npm_[A-Za-z0-9]{36}",
        "NPM access token detected.",
        "medium",
    ),
    (
        "Terraform Cloud Token",
        r"tfc\.[A-Za-z0-9]{34}",
        "Terraform Cloud API token detected.",
        "high",
    ),
    (
        "High Entropy Secret",
        r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{48,}(?![A-Za-z0-9+/=])",
        "High entropy string likely to be a credential.",
        "medium",
        _high_entropy_validator,
    ),
)

SECRET_PATTERNS: list[SecretPattern] = compile_patterns(PATTERN_DEFINITIONS)


SUSPICIOUS_FILENAMES: tuple[str, ...] = (
    "config.yaml",
    "config.yml",
    "config.json",
    "settings.py",
    "settings.json",
    "credentials.json",
    "credentials.yml",
    "credentials.ini",
    "secrets.json",
    "secrets.yml",
    "database.yml",
    "database.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "authorized_keys",
    "known_hosts",
    ".env",
    ".env.local",
    ".npmrc",
    ".aws/credentials",
    ".docker/config.json",
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
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".ps1",
    ".sh",
    ".bat",
    ".bak",
)

