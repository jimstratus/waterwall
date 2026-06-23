# Disclaimer

!!! danger "You assume all responsibility"
    Waterwall is provided **as-is**, without warranty of any kind. **You** are solely responsible
    for how you deploy, configure, and operate it, and for any consequences of doing so.

Please read this carefully before relying on Waterwall to protect anything you care about.

## No warranty

Waterwall is free and open-source software distributed under the [MIT License](license.html). To
the maximum extent permitted by law, it comes with **no warranty** — express or implied —
including but not limited to merchantability, fitness for a particular purpose, and
non-infringement. The authors and contributors are **not liable** for any claim, damages, data
loss, credential exposure, or other liability arising from its use.

## It is a homelab tool, not a security product

Waterwall is built for a **single trusted operator** on their own host. It is explicitly **not**:

- a multi-tenant or managed service,
- a substitute for a secrets manager, a DLP product, or a compliance program,
- tamper-**proof** — it is tamper-**evident**, and a root user on the host can forge its audit
  signatures (see the [Threat Model](threat-model.html)),
- a guarantee that **every** secret is caught. Redaction is pattern-based; an unknown credential
  format passes through until you add a pattern for it, and encoded payloads are not scanned.

## Not advice

Nothing in this documentation is legal, compliance, or professional security advice. The
compliance-framework tags Waterwall attaches to its audit log are **informational mappings**, not
a certification or an attestation of compliance with SOC 2, the EU AI Act, OWASP, MITRE ATLAS,
NIST, or any other framework.

## Your responsibilities

By using Waterwall you accept that you are responsible for:

- validating that it actually redacts what you expect in **your** environment before trusting it,
- protecting the signing key and CA key,
- keeping dependencies and clients up to date and re-verifying TLS interception after upgrades,
- complying with all laws, contracts, and provider terms of service that apply to intercepting
  and modifying your own API traffic.

If you do not accept these terms, do not use the software.
