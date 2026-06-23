# tests/test_patterns.py
"""Pattern set: every label in SAMPLES must match its corresponding sample;
each sample must be matched by exactly one label."""

import pytest
from waterwall.proxy.patterns import scan_string
from tests.fixtures.sample_secrets import SAMPLES, PEM_OPENSSH, PEM_RSA


@pytest.mark.parametrize("label,sample", list(SAMPLES.items()))
def test_each_sample_is_detected(label, sample):
    matches = scan_string(sample)
    assert len(matches) >= 1, f"sample for {label} produced no matches"
    assert any(m.type == label for m in matches), \
        f"sample for {label} matched {[m.type for m in matches]}, expected {label}"


def test_pem_openssh_block_detected():
    matches = scan_string(PEM_OPENSSH)
    assert any(m.type == "PEM_BLOCK" for m in matches)


def test_pem_rsa_block_detected():
    matches = scan_string(PEM_RSA)
    assert any(m.type == "PEM_BLOCK" for m in matches)


def test_pem_block_with_surrounding_text_still_detected():
    text = f"some prose\n{PEM_OPENSSH}\nmore prose"
    matches = scan_string(text)
    assert any(m.type == "PEM_BLOCK" for m in matches)


def test_pem_skipped_for_oversized_leaf():
    """Walker contract: leaves > 64 KiB skip the PEM scan (spec §8.2)."""
    huge = ("X" * 70_000) + PEM_OPENSSH
    matches = scan_string(huge)
    assert not any(m.type == "PEM_BLOCK" for m in matches), \
        "PEM scan should be skipped on > 64 KiB leaves"


def test_pure_hex_sha_does_not_match_sk_prefix():
    sha1_string = "a" * 40
    sha256_string = "a" * 64
    assert not any(m.type.startswith("OPENAI") for m in scan_string(sha1_string))
    assert not any(m.type.startswith("OPENAI") for m in scan_string(sha256_string))


class TestHomelabInventoryBatch2:
    """SOPS age keys + HashiCorp Vault tokens (issue #22). Mistral and the CF
    Global API Key were assessed and skipped as FP-prone (no distinctive
    prefix)."""

    def test_age_secret_key_detected(self):
        sample = "AGE-SECRET-KEY-1" + "Q" * 58
        assert any(m.type == "AGE_SECRET_KEY" for m in scan_string(f"sops key {sample} here"))

    def test_vault_service_token_detected(self):
        sample = "hvs." + "C" * 90
        assert any(m.type == "VAULT_TOKEN" for m in scan_string(f"token={sample}"))

    def test_vault_batch_token_detected(self):
        sample = "hvb." + "D" * 64
        assert any(m.type == "VAULT_TOKEN" for m in scan_string(sample))

    def test_vault_legacy_token_detected(self):
        sample = "s." + "f4X9aB2cD8eF1gH5jK7mN3pQ"[:24]
        assert len(sample) == 26
        assert any(m.type == "VAULT_TOKEN" for m in scan_string(f"VAULT_TOKEN={sample}"))

    def test_legacy_form_requires_exact_24(self):
        """23 or 25 trailing chars must NOT match — exact length is the only
        thing keeping the legacy `s.` form FP-safe."""
        assert not any(m.type == "VAULT_TOKEN" for m in scan_string("s." + "a" * 23))
        assert not any(m.type == "VAULT_TOKEN" for m in scan_string("s." + "a" * 25))

    def test_method_call_on_s_suffixed_identifier_is_not_a_token(self):
        """`this.someLongIdentifier...` — the `s` is mid-word, \\b blocks it."""
        text = "this.aBcDeFgHiJkLmNoPqRsTuVwX"
        assert len(text.split(".")[1]) == 24
        assert not any(m.type == "VAULT_TOKEN" for m in scan_string(text))

    def test_vault_recovery_token_detected(self):
        """hvr. recovery tokens are the highest-privilege Vault credential —
        exactly what gets pasted during a seal/rekey debugging session."""
        sample = "hvr." + "E" * 90
        assert any(m.type == "VAULT_TOKEN" for m in scan_string(sample))

    def test_vault_token_ending_in_dash_captured_in_full(self):
        """hv tokens are base64url; ~1/64 end in '-'. A trailing \\b would
        backtrack past the final '-', leaking the secret's last char."""
        sample = "hvs." + "A" * 28 + "-"
        matches = [m for m in scan_string(f"tok {sample} end") if m.type == "VAULT_TOKEN"]
        assert matches and matches[0].text == sample

    def test_property_chain_on_single_letter_s_is_not_a_token(self):
        """`a.s.<24 alnum>` — \\b holds between '.' and 's', so the legacy
        form needs a lookbehind to not fire on chained property access."""
        assert not any(
            m.type == "VAULT_TOKEN" for m in scan_string("a.s.aBcDeFgHiJkLmNoPqRsTuVwX")
        )

    def test_lowercase_age_secret_key_detected(self):
        """Bech32 is case-insensitive; tooling that lowercases (yaml
        normalizers, url handling) still yields a valid, working key."""
        sample = "age-secret-key-1" + "q" * 58
        assert any(m.type == "AGE_SECRET_KEY" for m in scan_string(sample))

    def test_age_key_with_non_bech32_chars_is_not_matched(self):
        """1/B/I/O are not in the Bech32 alphabet; a 58-char run containing
        them is not a valid age key data part."""
        assert not any(
            m.type == "AGE_SECRET_KEY"
            for m in scan_string("AGE-SECRET-KEY-1" + "B" * 58)
        )

    def test_age_recipient_public_key_is_not_matched(self):
        """age PUBLIC keys (age1...) are not secrets and must not match."""
        assert not any(
            m.type == "AGE_SECRET_KEY" for m in scan_string("age1" + "q" * 58)
        )


def test_policy_hash_is_stable():
    from waterwall.proxy.patterns import policy_hash
    h1 = policy_hash()
    h2 = policy_hash()
    assert h1 == h2
    assert len(h1) == 64
