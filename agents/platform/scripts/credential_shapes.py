"""The token shapes the platform scripts refuse to publish and redact before logging.

One list, read by two callers in two pods: `feedback_broker.validate` refuses a
report that carries any of them (a submission becomes a public issue), and
`credential_proxy.redact_credentials` blanks them out of a line the broker is
about to log (everything the broker writes leaves the cluster). Both used to
keep a list of their own, and the two had already diverged in grammar for the
same shape; this module is the one copy. It is seeded from the chart's
`AuditRedactor` (`charts/kube-agents/files/redactor.py`), which covers the
Hermes side and cannot be imported from here.

The sandbox image stages this file beside `feedback_broker.py`
(`deploy/sandbox/Dockerfile`), and the agent and broker images copy the whole
scripts tree, so each caller imports the same module wherever it runs.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

# The header value has two forms. The redactor masks any twelve letters after
# "bearer" or "basic", which costs a blanked word in a log line. The refusing
# gate requires a digit or a =, + or / in the value and sixteen characters,
# because "the basic troubleshooting steps" and "Bearer authentication returns
# 401" are the vocabulary of an auth bug report, and a refusal costs a person
# their report.
HEADER_VALUE_REDACT = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9_.=+/-]{12,}")
HEADER_VALUE_REFUSE = re.compile(r"(?i)\b(?:bearer|basic)\s+(?=[A-Za-z0-9_.=+/-]*[0-9=+/])[A-Za-z0-9_.=+/-]{16,}")

# (what the shape is, the pattern). The name is what a refusal says; it never
# echoes the match. Patterns apply to raw text: a caller that lowercases first
# loses the case-sensitive shapes (AKIA, the prefixed sk- tokens), so none does.
CREDENTIAL_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key material", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    # No leading word boundary on the GitHub shapes, as in the chart's list and
    # the proxy's before it: a token glued to the text before it, as a log line
    # truncated mid-word leaves it, is still a token.
    ("a GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("a fine-grained GitHub token", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("a Google OAuth token", re.compile(r"\bya29\.[0-9A-Za-z_.-]{20,}")),
    ("an AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b")),
    # The provider keys this install holds itself (LiteLLM's ANTHROPIC_API_KEY
    # and OPENAI_API_KEY): the bare sk- form and the prefixed one.
    ("a provider API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    (
        "a provider API key",
        re.compile(r"(?<![\w-])sk-(?:ant|proj|svcacct|admin)-(?=[A-Za-z0-9_-]*[A-Z])[A-Za-z0-9_-]{32,}"),
    ),
    ("a Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("an authorization header value", HEADER_VALUE_REDACT),
    # The proxy's grammar (8+ per segment) rather than the chart's (10+): the
    # looser one matches everything the stricter one does.
    ("a signed JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    (
        "a password in a URL",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s:/?#@\[\]\"'<>{}\\|^`,;]*:[^\s/?#\[\]\"'<>{}\\|^`,;]+@"),
    ),
)


# What the gate refuses: the redactor's list with the header value in its
# narrow form.
REFUSAL_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, HEADER_VALUE_REFUSE if pattern is HEADER_VALUE_REDACT else pattern)
    for name, pattern in CREDENTIAL_SHAPES
)

# Mandatory literal substrings for each entry in CREDENTIAL_SHAPES / REFUSAL_SHAPES
# in matching order. A tuple of strings means any one of them must appear in text
# (except ("://",), which requires both "://" and "@" in _may_contain_shape);
# None means the pattern is case-insensitive (checked via _BEARER_OR_BASIC_HINT_RE).
_SHAPE_HINTS: tuple[tuple[str, ...] | None, ...] = (
    ("PRIVATE KEY-----",),
    ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ("github_pat_",),
    ("AIza",),
    ("ya29.",),
    ("AKIA", "ASIA"),
    ("sk-",),
    ("sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-"),
    ("xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"),
    None,
    ("eyJ",),
    ("://",),  # paired with "@" in _may_contain_shape
)

# The case-insensitive hint for the header-value shape, searched in place so a
# multi-MiB text is never copied just to lowercase it. It matches wherever
# "bearer" or "basic" appears in any casing (and, through re's case folding,
# possibly a little more, which only costs a regex pass).
_BEARER_OR_BASIC_HINT_RE = re.compile(r"(?i:bearer|basic)")


def _may_contain_shape(text: str, hints: tuple[str, ...] | None) -> bool:
    if hints is None:
        return _BEARER_OR_BASIC_HINT_RE.search(text) is not None
    if hints == ("://",):
        return "://" in text and "@" in text
    for hint in hints:
        if hint in text:
            return True
    return False


def find_credential_shape(text: str) -> str | None:
    """The name of the first shape text carries that a public filing must refuse, or None."""
    if not text:
        return None
    for (name, pattern), hints in zip(REFUSAL_SHAPES, _SHAPE_HINTS, strict=True):
        if _may_contain_shape(text, hints) and pattern.search(text):
            return name
    return None


def redact(text: str) -> str:
    """text with every shape replaced by REDACTED."""
    if not text:
        return text
    for (_, pattern), hints in zip(CREDENTIAL_SHAPES, _SHAPE_HINTS, strict=True):
        if _may_contain_shape(text, hints):
            text = pattern.sub(REDACTED, text)
    return text
