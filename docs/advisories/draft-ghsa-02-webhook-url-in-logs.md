# DRAFT — GHSA 2 of 2: webhook URL written to logs in full

> **Status: unpublished draft.** Paste into
> <https://github.com/caisarus/euvd/security/advisories/new>. Replace this file with the
> published GHSA link once it is live. Fixed in `0.4.1`; text derived from the
> `CHANGELOG.md` `[0.4.1]` section and commit `e782fee`.

## Advisory form fields

| Field | Value |
| --- | --- |
| **Title** | euvd-watch logs the full webhook URL — the credential itself — on a failed delivery |
| **Ecosystem** | pip |
| **Package name** | `euvd-watch` |
| **Affected versions** | `< 0.4.1` |
| **Patched versions** | `0.4.1` |
| **Severity** | Moderate |
| **CVSS v3.1 vector (suggested)** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N` (6.5) |
| **CWE** | CWE-532 (Insertion of Sensitive Information into Log File) |
| **Credits** | caisarus — found in the internal pre-1.0 audit |
| **CVE** | Request one via the GHSA form (owner decision) |

Severity note: scope is rated Changed because the leaked secret belongs to the chat
platform, not to euvd-watch, and the disclosure lands wherever the logs go — for CI, that
is routinely a public location.

## Summary

Slack, Discord and Microsoft Teams all carry the secret **in the webhook URL path**, so the
URL is the credential. In every euvd-watch release before `0.4.1`, the retry and error
logging printed that URL in full on each failed delivery attempt.

## Impact

A transient delivery failure — nothing worse — writes **six WARNING lines containing a live
webhook token** (five retries plus the final error) to stderr, and therefore into CI logs,
which are public for most open-source projects. `docs/watch.md` actively encourages running
`watch --webhook` in CI, so the exposed configuration is the recommended one.

Anyone reading those logs can post arbitrary messages into the target channel.

## Patches

Upgrade to **`0.4.1`**:

```bash
pip install --upgrade "euvd-watch>=0.4.1"
```

Redaction is POST-scoped (`e782fee`): webhook lines now read
`https://hooks.slack.com/<redacted>`, keeping scheme and host so an operator still knows
which service failed. GET URLs are untouched, so EUVD paths stay readable for debugging, and
a test pins that distinction.

## Workarounds

For versions before `0.4.1`: do not pass `--webhook` in an environment whose logs are
readable by anyone who should not hold the webhook token, or suppress euvd-watch's WARNING
output on stderr.

## Remediation after upgrading

**Rotate any webhook URL that euvd-watch may have logged** — upgrading stops future leaks but
does not invalidate a token already written to a log. Slack, Discord and Teams all support
deleting and re-creating the webhook. Check archived CI logs for the affected runs.

## References

- `CHANGELOG.md`, section `[0.4.1]`
- Fix commit: `e782fee`
- `docs/watch.md` (webhook usage)
