"""Predefined secret detection patterns and helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Pattern
import re


@dataclass(frozen=True)
class SecretPattern:
    """Definition of a pattern that may indicate a secret."""

    name: str
    pattern: Pattern[str]
    description: str
    severity: str = "medium"


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
        r"glpat-[0-9a-zA-Z\-_]{20,}",
        "GitLab personal access token detected.",
        "high",
    ),
    (
        "Azure Storage Key",
        r'(?i)AccountKey=[A-Za-z0-9+/=]{52}',
        "Azure storage account key assignment detected.",
        "critical",
    ),
    (
        "Okta Token",
        r"00[a-zA-Z0-9-_]{40,}",
        "Okta token or client secret detected.",
        "high",
    ),
    (
        "NPM Access Token",
        r"npm_[A-Za-z0-9]{36}",
        "NPM access token signature.",
        "high",
    ),
    (
        "Google OAuth Refresh Token",
        r"1//[0-9A-Za-z_-]{43,}",
        "Google OAuth refresh token format.",
        "high",
    ),
    (
        "GitHub OAuth Token",
        r"gho_[A-Za-z0-9]{36}",
        "GitHub OAuth token signature.",
        "high",
    ),
    (
        "Mailgun API Key",
        r"key-[0-9a-zA-Z]{32}",
        "Mailgun API key detected.",
        "medium",
    ),
    (
        "Generic Bearer Token",
        r"Bearer\s+[A-Za-z0-9-_\.]{20,}",
        "Bearer authorization header with long opaque value.",
        "medium",
    ),
    (
        "Terraform State Secret",
        r'(?i)"?terraform_state"?\s*:\s*".{10,}"',
        "Terraform state reference with embedded secret.",
        "medium",
    ),
    (
        "Docker Auth Config",
        r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
        "Docker registry auth configuration containing credentials.",
        "medium",
    ),
    (
        "Service Account Key",
        r'"type"\s*:\s*"service_account"',
        "Google Cloud service account credential file.",
        "high",
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
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "vault.yml",
    "shadow",
    "htpasswd",
    "docker-compose.override.yml",
    "firebase-adminsdk.json",
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
    ".kdbx",
    ".sqlite",
    ".ovpn",
    ".cfg",
)


HIGH_ENTROPY_PATTERN = SecretPattern(
    name="High Entropy Candidate",
    pattern=re.compile(r""),
    description="High entropy string that resembles an encoded secret.",
    severity="medium",
)


ENTROPY_CANDIDATE_REGEX = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


ENV_FILE_HINTS: tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    "environment.yml",
    "vault.yml",
)


