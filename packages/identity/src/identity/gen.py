"""API key generator.

  python -m identity.gen
  python -m identity.gen --description "Production key for chatbot"

Prints the raw key once (operator copies into their secret manager),
and a YAML snippet to paste under an application's `keys:` list. The
raw key cannot be recovered later — only the hash is stored.

Format: `gw_live_<32 hex chars>`. The `gw_live_` prefix mirrors Stripe's
convention; operators recognize the shape, it's URL-safe, and the
prefix gives us room to add `gw_test_` later for non-production traffic.
"""
from __future__ import annotations

import argparse
import secrets
import sys
from datetime import datetime, timezone

from .store import hash_key


KEY_PREFIX = "gw_live_"
KEY_BYTES = 16  # → 32 hex chars after .hex()


def generate_key() -> tuple[str, str, str, str]:
    """Returns (raw_key, key_id, hash, prefix)."""
    raw = KEY_PREFIX + secrets.token_hex(KEY_BYTES)
    key_id = "key_" + secrets.token_hex(8)
    h = hash_key(raw)
    prefix = raw[:16]  # gw_live_<first 8 hex>
    return raw, key_id, h, prefix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a new API key for the AI gateway.")
    parser.add_argument("--description", "-d", default="", help="Optional description.")
    args = parser.parse_args(argv)

    raw, key_id, h, prefix = generate_key()
    created_at = datetime.now(timezone.utc).isoformat()

    # The raw key goes to STDERR so it doesn't accidentally end up in a
    # piped file with the YAML snippet. Operators see both, but only
    # the YAML is captured if they `>> identity.yaml`.
    print(f"Raw key (save this — it will not be shown again):", file=sys.stderr)
    print(f"  {raw}", file=sys.stderr)
    print("", file=sys.stderr)
    print("YAML snippet (paste under an application's `keys:` list):", file=sys.stderr)
    print("", file=sys.stderr)

    snippet = (
        f"          - id: {key_id}\n"
        f"            hash: \"{h}\"\n"
        f"            prefix: \"{prefix}\"\n"
        f"            created_at: \"{created_at}\"\n"
        f"            enabled: true\n"
    )
    if args.description:
        snippet += f"            description: \"{args.description}\"\n"
    print(snippet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
