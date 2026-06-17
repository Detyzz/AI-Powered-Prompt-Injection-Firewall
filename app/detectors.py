from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas import ThreatSignal


@dataclass(frozen=True)
class PatternRule:
    name: str
    pattern: re.Pattern[str]
    severity: str
    weight: int
    description: str


RULES: tuple[PatternRule, ...] = (
    PatternRule(
        name="instruction_override",
        pattern=re.compile(
            r"\b(ignore|forget|disregard|bypass|override)\b.{0,80}\b(previous|prior|above|system|developer|initial)\b.{0,40}\b(instruction|prompt|rule|message)s?\b",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        weight=35,
        description="Attempts to override higher-priority instructions.",
    ),
    PatternRule(
        name="role_manipulation",
        pattern=re.compile(
            r"\b(you are now|act as|pretend to be|roleplay as|simulate)\b.{0,80}\b(admin|root|developer|system|unfiltered|jailbreak|dan)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        weight=28,
        description="Tries to force the model into a privileged or unsafe role.",
    ),
    PatternRule(
        name="secret_exfiltration",
        pattern=re.compile(
            r"\b(reveal|print|show|dump|leak|exfiltrate|send)\b.{0,80}\b(system prompt|developer message|hidden instruction|api key|secret|token|credential)s?\b",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="high",
        weight=38,
        description="Requests hidden instructions, credentials, or sensitive data.",
    ),
    PatternRule(
        name="tool_abuse",
        pattern=re.compile(
            r"\b(call|use|execute|run)\b.{0,80}\b(tool|function|plugin|shell|python|browser|http request)\b.{0,80}\b(without asking|silently|in the background|do not tell)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="medium",
        weight=22,
        description="Attempts stealthy or unauthorized tool execution.",
    ),
    PatternRule(
        name="output_format_trap",
        pattern=re.compile(
            r"\b(output|respond|reply)\b.{0,80}\b(only|exactly|verbatim)\b.{0,80}\b(json|xml|yaml|base64|markdown)\b.{0,80}\b(no explanation|nothing else|do not include)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        severity="medium",
        weight=14,
        description="May be trying to constrain the model into bypassing safety checks.",
    ),
    PatternRule(
        name="encoded_payload",
        pattern=re.compile(
            r"\b(base64|rot13|hex|unicode|decode this|encoded message)\b",
            re.IGNORECASE,
        ),
        severity="medium",
        weight=16,
        description="Uses encoded or obfuscated instructions.",
    ),
)


def local_threat_analysis(prompt: str) -> dict:
    normalized = prompt.strip()
    signals: list[ThreatSignal] = []
    score = 0

    for rule in RULES:
        if rule.pattern.search(normalized):
            score += rule.weight
            signals.append(
                ThreatSignal(
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,  # type: ignore[arg-type]
                )
            )

    suspicious_density = _suspicious_keyword_density(normalized)
    if suspicious_density >= 4:
        score += min(20, suspicious_density * 3)
        signals.append(
            ThreatSignal(
                name="keyword_density",
                description="Contains many terms commonly seen in injection attempts.",
                severity="medium",
            )
        )

    if _has_long_delimiter_block(normalized):
        score += 10
        signals.append(
            ThreatSignal(
                name="delimiter_smuggling",
                description="Uses long delimiter blocks that can hide instruction boundaries.",
                severity="low",
            )
        )

    score = min(score, 100)
    category = _category_from_signals(signals)
    confidence = min(0.95, 0.35 + (score / 120))

    reasons = [signal.description for signal in signals]
    if not reasons:
        reasons = ["No obvious prompt injection indicators were detected."]

    return {
        "threat_score": score,
        "category": category,
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "signals": signals,
    }


def sanitize_prompt(prompt: str) -> str:
    """Remove common wrapper text while preserving user intent for safe downstream use."""

    sanitized = prompt.strip()
    sanitized = re.sub(
        r"(?i)\b(ignore|forget|disregard|bypass|override)\b.{0,100}\b(instruction|prompt|rule|message)s?\b",
        "[removed possible instruction override]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\b(reveal|print|show|dump|leak)\b.{0,80}\b(system prompt|developer message|api key|secret|token|credential)s?\b",
        "[removed possible sensitive-data request]",
        sanitized,
    )
    return sanitized[:12000]


def _suspicious_keyword_density(prompt: str) -> int:
    keywords = (
        "ignore",
        "bypass",
        "override",
        "jailbreak",
        "developer",
        "system prompt",
        "hidden",
        "secret",
        "token",
        "do not tell",
        "without restrictions",
        "unfiltered",
    )
    lowered = prompt.lower()
    return sum(1 for keyword in keywords if keyword in lowered)


def _has_long_delimiter_block(prompt: str) -> bool:
    return bool(re.search(r"(```|---|\[BEGIN\]|\[END\]|###).{300,}", prompt, re.DOTALL))


def _category_from_signals(signals: list[ThreatSignal]) -> str:
    names = {signal.name for signal in signals}
    if "secret_exfiltration" in names:
        return "secret_exfiltration"
    if "instruction_override" in names or "role_manipulation" in names:
        return "instruction_override"
    if "tool_abuse" in names:
        return "tool_abuse"
    if signals:
        return "suspicious"
    return "benign"
