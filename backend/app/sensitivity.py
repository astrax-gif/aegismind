"""Zero-trust data classifier.

Caller-declared `data_class` is authoritative. Content heuristics are a
backstop that can only ESCALATE sensitivity, never downgrade it.
"""
import re
from dataclasses import dataclass, field
from typing import Literal

DataClass = Literal["public", "private_code", "exploit"]

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "hardcoded_secret": re.compile(
        r"""(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['"][^'"]{8,}['"]"""
    ),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "db_conn_string": re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb)://[^\s:]+:[^\s@]+@"),
}
CODE_HINTS = re.compile(
    r"(?m)^\s*(?:def |class |import |from \w+ import |function |const |@app\.|SELECT .+ FROM )"
)
EXPLOIT_HINTS = re.compile(
    r"(?i)\b(shellcode|reverse shell|exploit chain|weaponi[sz]ed|working exploit)\b"
)


@dataclass(frozen=True)
class Sensitivity:
    sensitive: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)


def classify(text: str, data_class: DataClass = "public") -> Sensitivity:
    reasons: list[str] = []
    if data_class != "public":
        reasons.append(f"declared:{data_class}")
    for name, pat in SECRET_PATTERNS.items():
        if pat.search(text):
            reasons.append(f"secret:{name}")
    if CODE_HINTS.search(text):
        reasons.append("heuristic:source_code")
    if EXPLOIT_HINTS.search(text):
        reasons.append("heuristic:exploit_material")
    return Sensitivity(sensitive=bool(reasons), reasons=tuple(reasons))