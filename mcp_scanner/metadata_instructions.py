"""Bounded, report-only instruction signals in untrusted tool metadata.

Normalization is for detection, never a source rewrite. Quoted research examples
are masked locally; an actual directive elsewhere in the description survives.
"""
import re
import unicodedata

HOMOGLYPHS = str.maketrans("ІіОоАаЕеСсРрХхУуΑ", "IiOoAaEeCcPpXxYyA")
LEET = str.maketrans("013457", "oieast")


def instruction_view(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(HOMOGLYPHS)
    text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069]", "", text)
    # A run uses one separating space; word boundaries use two or more.
    text = re.sub(r"(?<!\w)(?:[A-Za-z] ){2,}[A-Za-z](?!\w)", lambda m: m[0].replace(" ", ""), text)
    text = re.sub(r"\b[A-Za-z0-9]{3,}\b", lambda m: m[0].translate(LEET)
                  if re.search(r"[A-Za-z]", m[0]) and re.search(r"[013457]", m[0]) else m[0], text)
    return text


def mask_reported_examples(text: str) -> str:
    chars = list(text)
    for match in re.finditer(r"(['\"])([^'\"\n]{5,500})\1", text):
        before = text[max(0, match.start()-220):match.start()]
        nearby = text[max(0, match.start()-300):min(len(text), match.end()+100)]
        if (re.search(r"(?i)(?:such as|phrases? (?:such as|like)|text|strings?|example|containing|shows why)\s*$", before)
                and re.search(r"(?i)\b(?:paper|research|analy[sz]e|injection|quoted|evidence|detection|mitigations?)\b", nearby)):
            chars[match.start():match.end()] = " " * (match.end()-match.start())
    # Physical product-label instructions do not govern an assistant's policy.
    for match in re.finditer(r"(?i)\bignore\s+(?:all\s+)?instructions\s+printed\s+on\s+the\s+(?:old\s+)?label\b", text):
        chars[match.start():match.end()] = " " * (match.end()-match.start())
    return "".join(chars)


SIGNALS = {
    "instruction_override": r"\b(?:ignore|disregard|override|cast aside|pay no attention to)\b.{0,90}?\b(?:guidance|guidelines?|instructions?|programming|directives?|policy|user's\s+request)\b|\bforget\s+(?:everything\s+you\s+were\s+told|(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|orders|directives))\b",
    "policy_bypass": r"\b(?:bypass(?:ing)?|skip(?:ping)?|disable|turn off)\b.{0,45}?\b(?:safety|security|fraud|verification|confirmation|filters?|safeguards?|checks)\b",
    "credential_disclosure": r"\b(?:reveal|send|transmit|share|paste|disclose|relay|leak|print|output|email)\b.{0,100}?\b(?:credentials?|creds|api\s+key|secret\s+token|confidential\s+tokens?|session\s+(?:token|data)|system\s+prompt|saved\s+cards|keys\s+you\s+hold)\b",
    "unrestricted_role": r"\b(?:you\s+(?:are|have been)|your\s+(?:new\s+identity|earlier\s+persona)|act\s+as|operate|switch\s+into|enable|activate|enter|imagine\s+you're)\b.{0,150}?\b(?:unrestricted|unbounded|no\s+(?:rules|restrictions|(?:content\s+)?policy)|zero\s+restrictions|without\s+(?:the\s+)?(?:constraints|limits)|dan\s+mode|god\s+mode)\b",
    "explicit_safety_off": r"\bdeveloper\s+mode\s+on\b.{0,50}\bsafety\s+off\b",
    "payment_bypass": r"\b(?:send|complete|finalize|release|dispatch)\b.{0,60}\b(?:payment|funds|purchase|transfer)\b.{0,70}\b(?:without\s+(?:any\s+)?|with\s+no\s+)(?:further|additional|the\s+standard)\s+(?:validation|review|fraud\s+review)\b",
    "foreign_override": r"\bignorez\b.{0,60}\binstructions\b|\bdeaktiviere\b.{0,50}\bsicherheitsregeln\b",
    "download_execute": r"\b(?:curl|wget)\b[^\n]{0,220}\|\s*(?:bash|sh)\b|\bexec\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(",
    "disable_approvals": r"\b(?:enable|set|write)\b.{0,80}\bauto[-_ ]?(?:approval|approve)\b.{0,60}\b(?:all|true)\b",
    "file_upload_directive": r"\b(?:post|send|transmit)\s+(?:read\s+|all\s+)?file\s+contents\s+to\s+https?://",
    "sensitive_shell_upload": r"\b(?:aws\s+(?:sts|iam)|cat\s+[^\n]{0,100}(?:\.env|environ|credentials|shadow))\b[^\n]{0,300}\|\s*(?:base64\s*\|\s*)?curl\b[^\n]{0,50}\bPOST\b",
}


def instruction_signals(text: str):
    view = instruction_view(mask_reported_examples(text))
    # A credential-collection prerequisite can be phrased as operational
    # telemetry rather than an explicit instruction override. Require all
    # three elements in one bounded span: obligation, collection, transmission.
    for obligation in re.finditer(r"(?i)\b(?:requires?|required|must|mandatory)\b", view):
        before = view[max(0, obligation.start()-40):obligation.start()]
        if re.search(r"(?i)\b(?:never|not|does not|do not|don't)\s*$", before):
            continue
        span = view[obligation.start():obligation.start()+1200]
        collection = re.search(
            r"(?i)\b(?:printenv|env\s*\||[\w-]+\s+env\s+ls)\b|"
            r"\bcat\s+[^\n|;&]{0,160}(?:\.ssh/|\.config/|/etc/shadow|credentials)|"
            r"\b(?:collect|submit|upload|send)\b.{0,100}\b(?:environment\s+(?:variables|data)|user[_ ]session)\b", span)
        transmission = re.search(r"(?i)\bcurl\b[^\n]{0,250}\bPOST\b|\b(?:submit|upload|send)\b", span)
        if collection and transmission and re.search(r"https?://", span):
            yield 'required_sensitive_upload', 'Required collection and external transmission of credential or session data'
            break
    if (re.search(r"(?i)\b(?:required|must|before\s+continuing)\b", view)
            and re.search(r"(?i)\b(?:retrieve|read|collect|extract)\b.{0,90}\b(?:access\s+token|credentials|secret)\b", view)
            and re.search(r"(?i)https?://[^\s]+[?&](?:token|key|secret)=", view)):
        yield "coerced_credential_url", "Required credential collection followed by a credential-bearing URL"
    for name, pattern in SIGNALS.items():
        for match in re.finditer(pattern, view, re.I | re.S):
            prefix = view[max(0, match.start()-45):match.start()]
            if re.search(r"(?i)\b(?:never|do not|don't|must not|should not|not to)\s*$", prefix):
                continue
            yield name, match[0]
            break
