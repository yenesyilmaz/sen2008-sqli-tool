# SQL injection detector: decode the input, match known attack patterns, count
# risky keywords and turn that into a 0-100 risk score.

import re
import urllib.parse
import html
from dataclasses import dataclass, field
from typing import List, Tuple
from core.payloads import SQLI_PATTERNS, DANGEROUS_KEYWORDS, WHITELIST_PATTERNS, RISK_WEIGHTS


@dataclass
class DetectionResult:
    input_value: str
    is_malicious: bool
    risk_score: int
    risk_level: str
    matched_patterns: List[str] = field(default_factory=list)
    matched_keywords: List[str] = field(default_factory=list)
    is_whitelisted: bool = False
    bypass_attempts: List[str] = field(default_factory=list)
    sanitized_value: str = ""


class SQLiDetector:
    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]
        self.whitelist = [re.compile(p, re.IGNORECASE) for p in WHITELIST_PATTERNS]

    def _is_whitelisted(self, value: str) -> bool:
        # fullmatch so the whole input must be safe, not just its start
        return any(p.fullmatch(value.strip()) for p in self.whitelist)

    def _normalize(self, value: str) -> Tuple[str, List[str]]:
        # Decode the input so an encoded payload can't slip past the patterns.
        bypasses = []
        normalized = value

        url_decoded = urllib.parse.unquote(value)
        if url_decoded != value:
            bypasses.append("URL encoding")
            normalized = url_decoded

        double_decoded = urllib.parse.unquote(normalized)
        if double_decoded != normalized:
            bypasses.append("double URL encoding")
            normalized = double_decoded

        html_decoded = html.unescape(normalized)
        if html_decoded != normalized:
            bypasses.append("HTML entity encoding")
            normalized = html_decoded

        def dehex(match):
            digits = match.group(1)
            if len(digits) % 2 != 0:
                return match.group(0)
            try:
                return bytes.fromhex(digits).decode("latin-1")
            except Exception:
                return match.group(0)

        hex_decoded = re.sub(r'0x([0-9a-fA-F]+)', dehex, normalized, flags=re.IGNORECASE)
        if hex_decoded != normalized:
            bypasses.append("hex encoding")
            normalized = hex_decoded

        char_pattern = re.compile(r'CHAR\s*\(\s*(\d+)\s*\)', re.IGNORECASE)
        if char_pattern.search(normalized):
            bypasses.append("CHAR() encoding")
            try:
                normalized = char_pattern.sub(lambda m: chr(int(m.group(1))), normalized)
            except Exception:
                pass

        # MySQL treats /**/ as whitespace, so replace with a space: this turns
        # UNION/**/SELECT into UNION SELECT instead of gluing the tokens together.
        comment_stripped = re.sub(r'/\*.*?\*/', ' ', normalized, flags=re.DOTALL)
        if comment_stripped != normalized:
            bypasses.append("inline comment")
            normalized = comment_stripped

        if '\x00' in normalized:
            bypasses.append("null byte")
            normalized = normalized.replace('\x00', '')

        return normalized, bypasses

    def _match_patterns(self, value: str) -> List[str]:
        return [SQLI_PATTERNS[i] for i, p in enumerate(self.patterns) if p.search(value)]

    def _check_keywords(self, value: str) -> List[str]:
        upper = value.upper()
        return [kw for kw in DANGEROUS_KEYWORDS if re.search(r'\b' + kw + r'\b', upper)]

    def _calculate_risk(self, matched_patterns, matched_keywords, bypasses, value) -> Tuple[int, str]:
        score = 0
        if matched_patterns:
            score += min(len(matched_patterns) * RISK_WEIGHTS["pattern_match"], 60)
        if matched_keywords:
            kw_score = len(matched_keywords) * (RISK_WEIGHTS["keyword_density"] // 4)
            score += min(kw_score, RISK_WEIGHTS["keyword_density"])
        special_chars = re.findall(r"['\";`\\]", value)
        if special_chars:
            score += min(len(special_chars) * 3, RISK_WEIGHTS["special_chars"])
        if bypasses:
            score += min(len(bypasses) * (RISK_WEIGHTS["encoding_bypass"] // 2),
                         RISK_WEIGHTS["encoding_bypass"])
        score = min(score, 100)

        if score == 0:
            level = "SAFE"
        elif score <= 25:
            level = "LOW"
        elif score <= 50:
            level = "MEDIUM"
        elif score <= 75:
            level = "HIGH"
        else:
            level = "CRITICAL"
        return score, level

    def analyze(self, value: str) -> DetectionResult:
        result = DetectionResult(
            input_value=value,
            is_malicious=False,
            risk_score=0,
            risk_level="SAFE",
            sanitized_value=self._sanitize(value),
        )

        if self._is_whitelisted(value):
            result.is_whitelisted = True
            return result

        normalized, bypasses = self._normalize(value)
        result.bypass_attempts = bypasses
        result.matched_patterns = self._match_patterns(normalized)
        result.matched_keywords = self._check_keywords(normalized)
        result.risk_score, result.risk_level = self._calculate_risk(
            result.matched_patterns, result.matched_keywords, bypasses, normalized
        )
        result.is_malicious = result.risk_score > 25
        return result

    def _sanitize(self, value: str) -> str:
        # Fallback escaping for the demo only; real code should use parameterized queries.
        sanitized = value.replace("'", "''").replace(";", "")
        sanitized = sanitized.replace("--", "").replace("/*", "").replace("*/", "")
        sanitized = re.sub(r'\b(EXEC|EXECUTE|xp_)\b', '', sanitized, flags=re.IGNORECASE)
        return sanitized.strip()
