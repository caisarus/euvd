# SPDX-License-Identifier: EUPL-1.2
"""Dashboard package (M6): consolidated state store now, FastAPI app in Step 6.2.

Nothing in `web.store` imports the `[web]` extra's dependencies — the store is stdlib
sqlite3 and is used by the core CLI; only `web serve` (Step 6.2) requires the extra.
"""
