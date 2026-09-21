"""Local, privacy-preserving password strength checker."""

from __future__ import annotations

import getpass
import re
import sys
from dataclasses import dataclass

MIN_SCORE = 0
MAX_SCORE = 100
MIN_USEFUL_LENGTH = 8
REPEAT_RUN_LENGTH = 3
SEQUENCE_RUN_LENGTH = 3
MAX_REPEATED_SUBSTRING_BLOCK = 4
COMMON_VARIANT_SUFFIX_LENGTH = 4

# Deliberately small list of obvious weak passwords. This is not a breached-
# password database and must never be represented as an exhaustive list.
COMMON_PASSWORDS = frozenset(
    {
        "123456",
        "12345678",
        "123456789",
        "password",
        "password1",
        "qwerty",
        "qwerty123",
        "admin",
        "letmein",
        "welcome",
        "abc123",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
    }
)

KEYBOARD_PATTERNS = (
    "qwerty",
    "qwert",
    "asdf",
    "asdfg",
    "zxcv",
    "zxcvb",
)

YEAR_PATTERN = re.compile(r"(?<![0-9])(?:19|20)[0-9]{2}(?![0-9])")

PENALTIES = {
    "common": 50,
    "short": 10,
    "sequence": 15,
    "repeat_char": 15,
    "repeat_substring": 10,
    "keyboard": 15,
    "year": 10,
}


@dataclass(frozen=True)
class PasswordAnalysis:
    """Derived password-strength information; never contains the password."""

    score: int
    level: str
    length: int
    has_lowercase: bool
    has_uppercase: bool
    has_digit: bool
    has_special: bool
    findings: tuple[str, ...]
    suggestions: tuple[str, ...]


def _length_points(length: int) -> int:
    if length >= 16:
        return 50
    if length >= 12:
        return 40
    if length >= 8:
        return 30
    if length >= 6:
        return 15
    return 0


def _strength_level(score: int) -> str:
    if score <= 24:
        return "Very Weak"
    if score <= 44:
        return "Weak"
    if score <= 69:
        return "Moderate"
    if score <= 84:
        return "Strong"
    return "Very Strong"


def _has_sequence(password: str, run_length: int = SEQUENCE_RUN_LENGTH) -> bool:
    """Detect contiguous ASCII alphanumeric runs with step +1 or -1."""
    if run_length < 2:
        raise ValueError("run_length must be at least 2")
    if len(password) < run_length:
        return False

    for start in range(len(password) - run_length + 1):
        window = password[start : start + run_length]
        if not all(char.isascii() and char.isalnum() for char in window):
            continue

        normalized = [char.lower() for char in window]
        codes = [ord(char) for char in normalized]
        step = codes[1] - codes[0]
        if step not in (-1, 1):
            continue
        if all(codes[index] - codes[index - 1] == step for index in range(1, len(codes))):
            return True
    return False


def _has_repeated_character_run(password: str, run_length: int = REPEAT_RUN_LENGTH) -> bool:
    """Detect a contiguous run of one identical code point."""
    if run_length < 2:
        raise ValueError("run_length must be at least 2")
    if not password:
        return False

    run = 1
    for index in range(1, len(password)):
        if password[index] == password[index - 1]:
            run += 1
            if run >= run_length:
                return True
        else:
            run = 1
    return False


def _has_repeated_substring(
    password: str, max_block_length: int = MAX_REPEATED_SUBSTRING_BLOCK
) -> bool:
    """Detect repeated multi-character blocks using a bounded algorithm."""
    if max_block_length < 1:
        raise ValueError("max_block_length must be positive")

    length = len(password)
    upper = min(max_block_length, length // 2)
    for block_length in range(2, upper + 1):
        for start in range(length - (2 * block_length) + 1):
            end = start + block_length
            first = password[start:end]
            if len(set(first)) == 1:
                continue
            if first == password[end : end + block_length]:
                return True
    return False


def _contains_common_password(password: str) -> bool:
    """Detect exact common passwords and only trivial decorations/variants."""
    if not password:
        return False

    compact = "".join(
        char for char in password.casefold() if char.isascii() and char.isalnum()
    )
    if compact in COMMON_PASSWORDS:
        return True

    for candidate in COMMON_PASSWORDS:
        if compact.startswith(candidate):
            suffix = compact[len(candidate) :]
            if 1 <= len(suffix) <= COMMON_VARIANT_SUFFIX_LENGTH and suffix.isdigit():
                return True
        if compact.endswith(candidate):
            prefix = compact[: -len(candidate)]
            if 1 <= len(prefix) <= COMMON_VARIANT_SUFFIX_LENGTH and prefix.isdigit():
                return True
    return False


def _contains_keyboard_pattern(password: str) -> bool:
    folded = password.casefold()
    return any(pattern in folded for pattern in KEYBOARD_PATTERNS)


def _contains_year(password: str) -> bool:
    return YEAR_PATTERN.search(password) is not None


def _character_classes(password: str) -> tuple[bool, bool, bool, bool]:
    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdecimal() for char in password)
    has_special = any(not char.isalnum() for char in password)
    return has_lowercase, has_uppercase, has_digit, has_special


def _build_findings(
    password: str,
    common: bool,
    short: bool,
    sequence: bool,
    repeated_char: bool,
    repeated_substring: bool,
    keyboard: bool,
    year: bool,
) -> tuple[str, ...]:
    findings: list[str] = []

    if not password:
        findings.append("Password is empty.")
    if short:
        findings.append("Password is very short.")
    if common:
        findings.append("Password matches a common weak-password pattern.")
    if sequence:
        findings.append("Contains an obvious ascending or descending sequence.")
    if repeated_char:
        findings.append("Contains a repeated-character run.")
    if repeated_substring:
        findings.append("Contains a repeated substring pattern.")
    if keyboard:
        findings.append("Contains a common keyboard pattern.")
    if year:
        findings.append("Contains a simple year-like sequence.")

    return tuple(findings)


def _build_suggestions(
    length: int,
    has_lowercase: bool,
    has_uppercase: bool,
    has_digit: bool,
    has_special: bool,
    findings: tuple[str, ...],
) -> tuple[str, ...]:
    suggestions: list[str] = []

    if length < 12:
        suggestions.append("Use a longer password or passphrase.")
    if not has_lowercase:
        suggestions.append("Add lowercase letters.")
    if not has_uppercase:
        suggestions.append("Add uppercase letters.")
    if not has_digit:
        suggestions.append("Add digits.")
    if not has_special:
        suggestions.append("Add special characters.")

    finding_text = " ".join(findings)
    if "common weak-password" in finding_text:
        suggestions.append("Avoid common passwords and trivial variations.")
    if "ascending or descending sequence" in finding_text:
        suggestions.append("Avoid predictable consecutive sequences.")
    if "repeated-character" in finding_text or "repeated substring" in finding_text:
        suggestions.append("Avoid repeated characters or repeated blocks.")
    if "keyboard pattern" in finding_text:
        suggestions.append("Avoid common keyboard patterns.")
    if "year-like" in finding_text:
        suggestions.append("Avoid obvious year-like numbers.")

    return tuple(dict.fromkeys(suggestions))


def analyze_password(password: str) -> PasswordAnalysis:
    """Analyze a password deterministically without retaining it in the result."""

    length = len(password)
    has_lowercase, has_uppercase, has_digit, has_special = _character_classes(password)

    common = _contains_common_password(password)
    short = length < MIN_USEFUL_LENGTH
    sequence = _has_sequence(password)
    repeated_char = _has_repeated_character_run(password)
    repeated_substring = _has_repeated_substring(password)
    keyboard = _contains_keyboard_pattern(password)
    year = _contains_year(password)

    findings = _build_findings(
        password,
        common,
        short,
        sequence,
        repeated_char,
        repeated_substring,
        keyboard,
        year,
    )

    class_points = sum(
        10 for present in (has_lowercase, has_uppercase, has_digit, has_special) if present
    )
    score = _length_points(length) + class_points
    score -= sum(
        (
            PENALTIES["common"] if common else 0,
            PENALTIES["short"] if short else 0,
            PENALTIES["sequence"] if sequence else 0,
            PENALTIES["repeat_char"] if repeated_char else 0,
            PENALTIES["repeat_substring"] if repeated_substring else 0,
            PENALTIES["keyboard"] if keyboard else 0,
            PENALTIES["year"] if year else 0,
        )
    )
    score = max(MIN_SCORE, min(MAX_SCORE, score))

    if common:
        score = min(score, 24)

    level = _strength_level(score)
    suggestions = _build_suggestions(
        length,
        has_lowercase,
        has_uppercase,
        has_digit,
        has_special,
        findings,
    )

    return PasswordAnalysis(
        score=score,
        level=level,
        length=length,
        has_lowercase=has_lowercase,
        has_uppercase=has_uppercase,
        has_digit=has_digit,
        has_special=has_special,
        findings=findings,
        suggestions=suggestions,
    )


def format_report(analysis: PasswordAnalysis) -> str:
    """Format derived analysis data without access to the password."""
    lines = [
        "Password Strength Checker",
        "-------------------------",
        "",
        f"Strength: {analysis.level}",
        f"Score: {analysis.score}/100",
        "",
        f"Password length: {analysis.length}",
        f"Lowercase: {'Yes' if analysis.has_lowercase else 'No'}",
        f"Uppercase: {'Yes' if analysis.has_uppercase else 'No'}",
        f"Digits: {'Yes' if analysis.has_digit else 'No'}",
        f"Special characters: {'Yes' if analysis.has_special else 'No'}",
    ]

    if analysis.findings:
        lines.extend(("", "Findings:"))
        lines.extend(f"- {finding}" for finding in analysis.findings)

    if analysis.suggestions:
        lines.extend(("", "Suggestions:"))
        lines.extend(f"- {suggestion}" for suggestion in analysis.suggestions)

    return "\n".join(lines)


def main() -> int:
    try:
        password = getpass.getpass("Enter password to check: ")
        analysis = analyze_password(password)
        print()
        print(format_report(analysis))
        return 0
    except (EOFError, KeyboardInterrupt):
        print("\nOperation cancelled.")
        return 130
    except Exception:
        print("Could not analyze the password safely.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
