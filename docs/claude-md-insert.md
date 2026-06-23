# Waterwall placeholder protocol — paste into ~/.claude/CLAUDE.md

This is the system-prompt nudge that makes IAM-agent workflows round-trip
correctly through waterwall. Without it, Claude paraphrases tokenized secrets
into descriptive text (`<your_key>`, `<API_KEY>`, etc.) and the local
detokenizer can't substitute the real value back.

Append the following block to your `~/.claude/CLAUDE.md` (or to a per-project
`./CLAUDE.md` if you want scoped behavior). Wording is precise — copy verbatim.

---

## Waterwall placeholder protocol

When you receive input containing strings of the form `<pl:TYPE:HEX>` (e.g.
`<pl:AWS_ACCESS_KEY:abc12345>`, `<pl:ANTHROPIC_KEY:def67890>`,
`<pl:GITHUB_TOKEN:0011223344556677>`), they are opaque references to a real
secret held by a local egress proxy. **Never** paraphrase, abbreviate, elide,
or replace these with descriptive placeholders like `<your_key>`, `<API_KEY>`,
`<...>`, or "the AWS key". Reproduce each placeholder string byte-for-byte
in your output if you reference it.

Why this matters: the proxy detokenizes your response on its way back to the
local agent, restoring placeholders to their original secret values. That
substitution only fires on exact matches of the `<pl:TYPE:HEX>` form. If you
reword them, the local agent receives the placeholder text instead of the
actual secret, and any operational command (vault, sops, write to .env, etc.)
fails or silently writes garbage.

When generating commands or code that includes such a placeholder, treat it
exactly like a literal string variable — quote it where the shell needs
quoting, but never alter its content.

If you have any uncertainty whether to preserve a placeholder verbatim or
treat it as opaque, prefer verbatim preservation. There is no scenario in
which paraphrasing improves the outcome.

---

## Verifying the protocol works

After installing, paste a synthetic AKIA key into a claude session and ask
Claude to "generate a vault command to store this under secret/aws/test".
The output should contain the placeholder verbatim (e.g.
`vault kv put secret/aws/test access_key=<pl:AWS_ACCESS_KEY:abc12345>`),
and the proxy will substitute the real key on the way back. Run that command
literally — Vault should store the original AKIA value.

If Claude responds with `<your_aws_key>` or `<...>` style placeholders, the
nudge isn't being applied — verify CLAUDE.md is loaded by the running claude
process (`/help` shows project memory state in the in-app viewer).
