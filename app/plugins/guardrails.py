import re
import unicodedata

# Lookalike characters (Cyrillic/Greek) folded to ASCII before detection and redaction.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "һ": "h", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "κ": "k", "ℓ": "l",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y", "І": "I", "Ј": "J",
})

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.I)
OBFUSCATED_RE = re.compile(r"\b[A-Za-z0-9._%+-]+(?:\s*\[(?:at|dot)\]\s*)[A-Za-z0-9.-]+\b", re.I)
# Spelled-out email: "jane dot doe at corp dot example", "jane.doe AT corp DOT example"
SPELLED_EMAIL_RE = re.compile(
    r"\b[\w+-]+(?:\.[\w+-]+)*(?:\s+dot\s+[\w+-]+)*\s+at\s+[\w-]+(?:\s+[\w-]+)?\s+dot\s+[a-z]{2,}\b", re.I,
)
SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
SSN_SPACED_RE = re.compile(r"(?<!\d)\d{3}[ ]\d{2}[ ]\d{4}(?!\d)")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?){1,2}\d{3,4}(?!\d)")
DIGIT_WORDS_RE = re.compile(
    r"\b(?:(?:zero|one|two|three|four|five|six|seven|eight|nine|oh)\b[\s-]*){9,}", re.I,
)

# Direct-injection patterns, matched on folded lowercase text.
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+|any\s+|the\s+|your\s+|of\s+|these\s+)*(?:previous|prior|above|earlier|preceding|foregoing|guardrails?|rules|instructions|directions|guidance|polic(?:y|ies))\b",
    r"disregard\s+(?:all\s+|any\s+|of\s+|the\s+|your\s+|these\s+|those\s+)*(?:rules?|instructions?|directions?|polic(?:y|ies)|guidance|guidelines?|previous|prior)\b",
    r"forget\s+(?:everything|all|what|your|the\s+(?:rules|instructions|policy|polic(?:y|ies)))\b",
    r"\bsystem\s+(?:prompt|message|override|instructions?)\b",
    r"\b(?:hidden|initial|original|confidential|internal|secret)\s+(?:prompt|instructions?|configuration|config|rules|tokens?|secrets?)\b",
    r"\b(?:reveal|print|show|output|repeat|quote|dump|leak|copy|tell\s+me|list)\s+(?:me\s+)?(?:your|the\s+(?:full\s+)?(?:system|hidden|initial|original|confidential|internal|secret))\b[^.?!\n]{0,40}\b(?:prompt|instructions?|configuration|config|rules|message|secrets?|tokens?)\b",
    r"\bwhat\s+(?:were\s+you\s+told|(?:instructions|rules|prompt|configuration)\s+(?:were|was|are)\s+you\s+(?:given|told|configured))\b",
    r"\byou\s+are\s+now\b[^.?!\n]{0,40}\b(?:without|no)\s+(?:restrictions?|limits?|rules?|filters?|content\s+policy|policy)\b",
    r"\bno\s+(?:content\s+)?(?:policy|rules|restrictions)\s+(?:anymore|left|apply)\b",
    r"\b(?:enable|enter|switch\s+to|activate|turn\s+on)\s+(?:the\s+)?(?:dan|developer|unrestricted|jailbreak)\s+mode\b",
    r"\bjailbreak\b",
    r"\b(?:bypass|override|circumvent|skip|disable|turn\s+off|remove)\s+(?:the\s+|all\s+|any\s+|this\s+|every\s+|your\s+)*(?:safety|policy|policies|controls?|checks?|reviews?|gates?|hitl|human|approvals?|verification|shield|injection|guardrails?|rules?|restrictions?)\b",
    r"\bwithout\s+(?:any\s+)?(?:restrictions?|limits?|filters?|approval|review|verification|checks?|hitl)\b",
    r"\b(?:grant|give)\s+(?:me\s+|yourself\s+)?(?:full|admin|root|unrestricted)\s+access\b",
    r"\b(?:act|acting|behave)\s+as\s+(?:the\s+|an?\s+)?(?:root|administrator|admin|ceo|cto|developer|system|superuser|owner)\b",
    r"\bas\s+(?:the\s+|an?\s+)?(?:ceo|cto|cfo|administrator|admin|root|developer|owner|safety\s+officer|vp|manager)\b[^.?!\n]{0,40}\b(?:authori[sz]e[ds]?|authority|permission)\b",
    r"\b(?:translate|repeat|quote)\s+(?:your|the)\s+(?:hidden\s+|system\s+|initial\s+)?(?:instructions|prompt)\b|\brepeat\s+the\s+text\s+above\b|\bprint\s+everything\s+above\b",
    r"\[\s*system\s*\]|\bsystem\s+override\b|\bnew\s+rule\s*:|\bend\s+of\s+user\s+message\b",
    r"\bpretend\s+(?:the\s+|that\s+the\s+)?(?:policy|rules?|guidelines?)\s+(?:does\s+not|doesn'?t)\s+apply\b",
    r"\b(?:override|bypass|ignore)\s+(?:the\s+)?(?:policy|policies|rules|gates?)\b",
]

# Indirect-injection patterns: instructions planted inside retrieved content.
CONTEXT_INJECTION_PATTERNS = [
    r"<!--[^>]*(?:admin|system|ignore|instruction|assistant)",
    r"\bnote\s+to\s+(?:the\s+)?assistant\b",
    r"\bassistant\s*[,:]\s*(?:approve|ignore|reply|respond|state|print|answer|output|skip|mark|call)\b",
    r"\bdirective\s+for\s+the\s+model\b|\bfor\s+the\s+model\b[^.\n]{0,20}\b(?:respond|reply|answer|output)\b",
    r"\btool\s+instruction\s*:|\bdeveloper\s+note\s*:|\bcompliance\s+team\s+says\b",
    r"\bwhen\s+summari[sz]ing\s+this\s+chunk\b",
    r"\bmutation\s+executed\b|\bpre-approved\s+by\s+reviewer\b",
]

_INJECTION_RE = re.compile("|".join(f"(?:{p})" for p in INJECTION_PATTERNS))
_CONTEXT_RE = re.compile("|".join(f"(?:{p})" for p in CONTEXT_INJECTION_PATTERNS))


def normalize_unicode(text: str) -> str:
    return unicodedata.normalize("NFKC", text).strip()


def fold_confusables(text: str) -> str:
    return text.translate(CONFUSABLES)


def _fold_separators(text: str) -> str:
    text = re.sub(r"\s*[\(\[]\s*at\s*[\)\]]\s*", "@", text, flags=re.I)
    text = re.sub(r"\s*[\(\[]\s*dot\s*[\)\]]\s*", ".", text, flags=re.I)
    return text


def redact_pii(text: str) -> tuple[str, bool]:
    folded = fold_confusables(normalize_unicode(text))
    redacted = OBFUSCATED_RE.sub("[REDACTED_EMAIL]", folded)
    redacted = _fold_separators(redacted)
    redacted = SPELLED_EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
    redacted = EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
    redacted = SSN_RE.sub("[REDACTED_SSN]", redacted)
    redacted = SSN_SPACED_RE.sub("[REDACTED_SSN]", redacted)
    redacted = DIGIT_WORDS_RE.sub("[REDACTED_ID]", redacted)
    redacted = PHONE_RE.sub("[REDACTED_PHONE]", redacted)
    return redacted, "[REDACTED_" in redacted


def injection_detected(text: str) -> bool:
    folded = fold_confusables(unicodedata.normalize("NFKC", text)).lower()
    return bool(_INJECTION_RE.search(folded))


def context_injection_detected(text: str) -> bool:
    """Instructions hidden in retrieved content. Checked on every chunk before it can enter the prompt."""
    folded = fold_confusables(unicodedata.normalize("NFKC", text)).lower()
    return bool(_INJECTION_RE.search(folded) or _CONTEXT_RE.search(folded))


def repair_argument(value: str) -> str:
    sku = re.fullmatch(r"SKU\s*(\d+)", value, re.I)
    if sku:
        return f"SKU-{int(sku.group(1)):03d}"
    lot = re.fullmatch(r"LOT\s*(\d+)", value, re.I)
    if lot:
        return f"LOT-{int(lot.group(1)):05d}"
    return value.strip()
