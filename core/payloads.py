# Attack signatures, risky keywords, the safe-input whitelist and scoring weights.

SQLI_PATTERNS = [
    # Boolean / tautology
    r"('|\"|`)\s*(OR|AND)\s+('|\"|`)?[0-9a-zA-Z]+('|\"|`)?\s*(=|LIKE)\s*('|\"|`)?[0-9a-zA-Z]+",
    r"\bOR\b\s+1\s*=\s*1",
    r"\bAND\b\s+1\s*=\s*1",
    r"\bOR\b\s+['\"]\w+['\"]=['\"]\w+['\"]",
    # UNION
    r"\bUNION\b\s+(ALL\s+)?\bSELECT\b",
    # Error-based
    r"\bEXTRACTVALUE\b\s*\(",
    r"\bUPDATEXML\b\s*\(",
    r"\bCONVERT\b\s*\(.*\bUSING\b",
    # Stacked queries
    r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b",
    # Comment right after a quote (e.g. admin'--); kept tight so "C#" is not flagged
    r"['\"`]\s*(--|#)",
    # Time-based blind
    r"\bSLEEP\b\s*\(\s*\d+\s*\)",
    r"\bWAITFOR\b\s+\bDELAY\b",
    r"\bBENCHMARK\b\s*\(",
    # Dangerous functions
    r"\bLOAD_FILE\b\s*\(",
    r"\bINTO\b\s+(OUT|DUMP)FILE\b",
    r"\bEXEC\b\s*(\(|sp_|xp_)",
    r"\bxp_cmdshell\b",
    # Encoding tricks
    r"(0x[0-9a-fA-F]+)",
    r"(CHAR|CHR)\s*\(\s*\d+",
    r"(URL|HTML|BASE64)\s*decode",
]

DANGEROUS_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
    "ALTER", "EXEC", "EXECUTE", "UNION", "HAVING", "GROUP BY",
    "ORDER BY", "LOAD_FILE", "OUTFILE", "DUMPFILE", "BENCHMARK",
    "SLEEP", "WAITFOR", "INFORMATION_SCHEMA", "SYS", "MYSQL",
    "XP_CMDSHELL", "SP_EXECUTESQL",
]

# Inputs matching one of these in full are treated as safe, so legitimate values
# that contain an apostrophe (e.g. the surname O'Connor) are not flagged.
WHITELIST_PATTERNS = [
    r"[A-Z][a-zA-Z]*'[A-Z][a-z]+",                              # O'Connor, D'Angelo
    r"\w+'s",                                                   # user's, admin's
    r"(don't|can't|won't|it's|that's|i'm|you're|we're|isn't|aren't)",
]

RISK_WEIGHTS = {
    "pattern_match": 40,
    "keyword_density": 20,
    "special_chars": 15,
    "encoding_bypass": 25,
}
