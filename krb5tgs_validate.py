#!/usr/bin/env python3
"""
krb5tgs_validate.py — Parse and validate Kerberos 5 TGS-REP Kerberoast hashes.

Covers Hashcat modes:
    13100  etype 23  RC4-HMAC
    19600  etype 17  AES128-CTS-HMAC-SHA1-96
    19700  etype 18  AES256-CTS-HMAC-SHA1-96

Format expected:
    $krb5tgs$<etype>$<user>$<realm>$<checksum>$<edata2>

Note on the older RC4 (13100) shape:
    $krb5tgs$23$*user$realm$spn*$checksum$edata2
    (the user/realm/spn live in a '*...*' block). This tool handles both.

No third-party deps. Pure stdlib. Structural validation only — it does NOT
decrypt or crack. It checks field presence, etype sanity, hex-ness, and the
96-bit checksum width that AES etypes must have.
"""

import argparse
import re
import sys

ETYPE_INFO = {
    "17": {
        "name": "AES128-CTS-HMAC-SHA1-96",
        "hashcat_mode": 19600,
        "checksum_bytes": 12,   # 96-bit truncated HMAC-SHA1
        "salted": True,
        "kdf_iters": 4096,
    },
    "18": {
        "name": "AES256-CTS-HMAC-SHA1-96",
        "hashcat_mode": 19700,
        "checksum_bytes": 12,   # 96-bit truncated HMAC-SHA1
        "salted": True,
        "kdf_iters": 4096,
    },
    "23": {
        "name": "RC4-HMAC",
        "hashcat_mode": 13100,
        "checksum_bytes": 16,   # 128-bit HMAC-MD5
        "salted": False,
        "kdf_iters": None,
    },
}

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class ParseResult:
    def __init__(self):
        self.ok = True
        self.etype = None
        self.user = None
        self.realm = None
        self.spn = None          # only present in RC4 '*...*' form
        self.checksum = None
        self.edata2 = None
        self.errors = []
        self.warnings = []
        self.info = {}

    def fail(self, msg):
        self.ok = False
        self.errors.append(msg)


def _is_hex(s):
    return bool(s) and bool(HEX_RE.match(s))


def parse_hash(raw):
    """Parse one hash line into a ParseResult. Structural checks only."""
    r = ParseResult()
    line = raw.strip()

    if not line.startswith("$krb5tgs$"):
        r.fail("Missing '$krb5tgs$' signature — not a TGS-REP Kerberoast hash.")
        return r

    body = line[len("$krb5tgs$"):]

    # Pull etype first (everything up to the next '$').
    etype, sep, rest = body.partition("$")
    if not sep:
        r.fail("Truncated after signature; no etype field.")
        return r
    r.etype = etype

    if etype not in ETYPE_INFO:
        r.fail(f"Unknown/unsupported etype '{etype}' "
               f"(expected 17, 18, or 23).")
        # keep going so we can still report structure where possible
    else:
        r.info = dict(ETYPE_INFO[etype])

    # Two shapes depending on etype/tooling:
    #   RC4 classic:  *user$realm$spn*$checksum$edata2
    #   AES / modern: user$realm$checksum$edata2
    if rest.startswith("*"):
        # RC4-style principal block delimited by '*...*'
        m = re.match(r"^\*(.*?)\*\$(.+)$", rest)
        if not m:
            r.fail("Malformed '*user$realm$spn*' principal block.")
            return r
        principal, tail = m.group(1), m.group(2)
        pparts = principal.split("$")
        if len(pparts) == 3:
            r.user, r.realm, r.spn = pparts
        elif len(pparts) == 2:
            r.user, r.realm = pparts
        else:
            r.fail(f"Principal block has {len(pparts)} parts; expected 2–3 "
                   f"(user/realm[/spn]).")
            return r
        tail_parts = tail.split("$")
        if len(tail_parts) != 2:
            r.fail(f"Expected checksum$edata2 after principal block; "
                   f"got {len(tail_parts)} segment(s).")
            return r
        r.checksum, r.edata2 = tail_parts
    else:
        # user$realm$checksum$edata2
        parts = rest.split("$")
        if len(parts) != 4:
            r.fail(f"Expected 4 fields (user/realm/checksum/edata2) after "
                   f"etype; got {len(parts)}.")
            # Try a best-effort assignment for reporting if close.
            if len(parts) >= 4:
                r.user, r.realm, r.checksum = parts[0], parts[1], parts[2]
                r.edata2 = "$".join(parts[3:])
            return r
        r.user, r.realm, r.checksum, r.edata2 = parts

    _validate_fields(r)
    return r


def _validate_fields(r):
    # Empty-field checks
    if not r.user:
        r.fail("Empty user/principal field.")
    if not r.realm:
        r.fail("Empty realm field.")
    if not r.checksum:
        r.fail("Empty checksum field.")
    if not r.edata2:
        r.fail("Empty edata2 (ciphertext) field.")

    # Realm casing is load-bearing for AES salt; warn, don't fail.
    if r.realm and r.realm != r.realm.upper():
        r.warnings.append(
            f"Realm '{r.realm}' is not uppercase. AES salt = "
            f"UPPERREALM+principal, so mixed case can break cracking."
        )

    # Checksum: must be hex and correct width for the etype.
    if r.checksum:
        if not _is_hex(r.checksum):
            r.fail("Checksum contains non-hex characters.")
        elif len(r.checksum) % 2 != 0:
            r.fail(f"Checksum hex length {len(r.checksum)} is odd "
                   f"(not whole bytes).")
        else:
            cbytes = len(r.checksum) // 2
            expected = r.info.get("checksum_bytes")
            if expected and cbytes != expected:
                r.fail(f"Checksum is {cbytes} bytes ({len(r.checksum)} hex "
                       f"chars); etype {r.etype} requires {expected} bytes "
                       f"({expected*2} hex chars).")

    # edata2: must be hex, even length, and non-trivially sized.
    if r.edata2:
        if not _is_hex(r.edata2):
            r.fail("edata2 contains non-hex characters.")
        elif len(r.edata2) % 2 != 0:
            r.fail(f"edata2 hex length {len(r.edata2)} is odd "
                   f"(not whole bytes).")
        else:
            ebytes = len(r.edata2) // 2
            # Minimum: AES confounder(16) + some enc-part. Anything under
            # ~32 bytes is almost certainly a mangled/truncated paste.
            if ebytes < 32:
                r.warnings.append(
                    f"edata2 is only {ebytes} bytes — suspiciously short "
                    f"for a real ticket enc-part; check for truncation."
                )
            r.info["edata2_bytes"] = ebytes


def format_report(r, raw, idx=None, verbose=False):
    lines = []
    tag = f"[{idx}] " if idx is not None else ""
    status = "VALID" if r.ok else "INVALID"
    mark = "OK " if r.ok else "XX "
    lines.append(f"{mark}{tag}{status}")

    if r.etype:
        info = ETYPE_INFO.get(r.etype, {})
        name = info.get("name", "unknown")
        mode = info.get("hashcat_mode", "?")
        lines.append(f"     etype:    {r.etype} ({name})")
        lines.append(f"     hashcat:  -m {mode}")
    if r.user is not None:
        lines.append(f"     user:     {r.user}")
    if r.realm is not None:
        lines.append(f"     realm:    {r.realm}")
    if r.spn:
        lines.append(f"     spn:      {r.spn}")
    if r.checksum is not None:
        cb = len(r.checksum)//2 if _is_hex(r.checksum) else "?"
        lines.append(f"     checksum: {len(r.checksum)} hex / {cb} bytes")
    if r.edata2 is not None:
        eb = r.info.get("edata2_bytes", "?")
        if verbose:
            lines.append(f"     edata2:   {len(r.edata2)} hex / {eb} bytes")
            lines.append(f"               {r.edata2}")
        else:
            preview = (r.edata2[:48] + "...") if len(r.edata2) > 48 else r.edata2
            lines.append(f"     edata2:   {len(r.edata2)} hex / {eb} bytes "
                         f"({preview})")
    if r.info.get("salted") is not None and r.etype in ETYPE_INFO:
        salted = r.info["salted"]
        if salted:
            salt = f"{(r.realm or 'REALM')}{r.user or 'user'}"
            lines.append(f"     salt:     {salt}  "
                         f"(PBKDF2-HMAC-SHA1, {r.info.get('kdf_iters')} iters)")
        else:
            lines.append(f"     salt:     none (unsalted RC4)")

    for w in r.warnings:
        lines.append(f"     ! warn:   {w}")
    for e in r.errors:
        lines.append(f"     X error:  {e}")

    return "\n".join(lines)


def iter_input(args):
    if args.hash:
        yield args.hash
    elif args.file:
        if args.file == "-":
            for ln in sys.stdin:
                if ln.strip():
                    yield ln
        else:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                for ln in fh:
                    if ln.strip():
                        yield ln
    else:
        # default: read stdin if piped
        if not sys.stdin.isatty():
            for ln in sys.stdin:
                if ln.strip():
                    yield ln


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Validate Kerberos 5 TGS-REP Kerberoast hashes "
                    "(hashcat 13100/19600/19700).")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("hash", nargs="?", help="a single hash string")
    g.add_argument("-f", "--file", help="file of hashes (one per line), "
                                         "or '-' for stdin")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print full edata2 instead of a preview")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="only print a summary count + invalid lines")
    args = ap.parse_args(argv)

    total = valid = invalid = 0
    for i, raw in enumerate(iter_input(args), 1):
        r = parse_hash(raw)
        total += 1
        if r.ok:
            valid += 1
        else:
            invalid += 1
        if args.quiet:
            if not r.ok:
                print(format_report(r, raw, idx=i, verbose=args.verbose))
        else:
            print(format_report(r, raw, idx=i, verbose=args.verbose))
            print()

    if total == 0:
        print("No input. Pass a hash, use -f FILE, or pipe via stdin.",
              file=sys.stderr)
        return 2

    print(f"--- {valid}/{total} valid, {invalid} invalid ---")
    return 0 if invalid == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
