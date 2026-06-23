# tests/fixtures/sample_secrets.py
"""Synthetic test values for each supported pattern. NONE are real credentials."""

SAMPLES: dict[str, str] = {
    "ANTHROPIC_KEY":         "sk-ant-api03-" + "A" * 95,
    "ANTHROPIC_OAUTH_TOKEN": "sk-ant-oat01-" + "B" * 100,
    "OPENAI_KEY":            "sk-proj-" + "C" * 50,
    "AWS_ACCESS_KEY":        "AKIAIOSFODNN7EXAMPLE",
    "GITHUB_TOKEN":          "ghp_" + "D" * 36,
    "CLOUDFLARE_API_TOKEN":  "cfk_" + "E" * 40,
    "SUPABASE_SECRET_KEY":   "sb_secret_" + "F" * 30,
    "GROQ_KEY":              "gsk_" + "G" * 50,
    "VERCEL_TOKEN":          "vrcl_" + "H" * 30,
    "JWT_TOKEN":             "eyJ" + "I" * 30 + "." + "J" * 40 + "." + "K" * 50,
    "TWILIO_ACCOUNT_SID":    "AC" + "f" * 32,
    "TWILIO_API_KEY":        "SK" + "a" * 32,
    "SENDGRID_KEY":          "SG." + "L" * 30 + "." + "M" * 50,
    "LINEAR_API_KEY":        "lin_api_" + "N" * 35,
    "NOTION_TOKEN":          "ntn_" + "O" * 40,
    "ATLASSIAN_TOKEN":       "ATATT3" + "P" * 35,
    "HUGGINGFACE_TOKEN":     "hf_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "PERPLEXITY_KEY":        "pplx-" + "Q" * 48,
    "DROPBOX_KEY":           "dpf_" + "R" * 45,
    "TURSO_KEY":             "tfp_" + "S" * 45,
    # HCV-inventory uplift batch 1 (formats verified on prod-host 2026-05-09 via no-leak shape probe)
    "GOOGLE_AI_KEY":         "AIza" + "T" * 35,
    "OPENROUTER_KEY":        "sk-or-v1-" + "a" * 64,
    "DISCORD_BOT_TOKEN":     "M" + "U" * 25 + "." + "V" * 6 + "." + "W" * 30,
    "TELEGRAM_BOT_TOKEN":    "1234567890:" + "X" * 35,
    "ELEVENLABS_KEY":        "sk_" + "a" * 48,
    "JINA_KEY":              "jina_" + "Y" * 60,
    "BRAVE_SEARCH_KEY":      "BSA" + "Z" * 28,
    "CLICKUP_TOKEN":         "pk_12345678_" + "A" * 32,
    # Homelab-inventory batch 2 (issue #22)
    "AGE_SECRET_KEY":        "AGE-SECRET-KEY-1" + "Q" * 58,
    "VAULT_TOKEN":           "hvs." + "C" * 90,
}

def _make_fake_pem(kind: str) -> str:
    """Build a fake PEM block at runtime so source contains no static
    BEGIN/END+body literal that would trip secret scanners.
    The body is unmistakably not a real key."""
    begin = "-----BEGIN " + kind + " PRIVATE KEY-----"
    end   = "-----END "   + kind + " PRIVATE KEY-----"
    body  = "FIXTURE-NOT-A-REAL-KEY-do-not-decode-test-only"
    return f"{begin}\n{body}\n{end}"


PEM_OPENSSH = _make_fake_pem("OPENSSH")
PEM_RSA     = _make_fake_pem("RSA")
