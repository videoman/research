#!/usr/bin/env python3
"""
krb5tgs_validate.py — Parse and validate Kerberos 5 TGS-REP Kerberoast hashes.

Covers Hashcat modes:
    13100  etype 23  RC4-HMAC
    19600  etype 17  AES128-CTS-HMAC-SHA1-96
    19700  etype 18  AES256-CTS-HMAC-SHA1-96

Recognized layouts (Impacket GetUserSPNs / Rubeus):

    RC4 (23):   $krb5tgs$23$*user$realm$spn*$checksum$edata2
                  - principal block '*user$realm$spn*' up front
                  - checksum = FIRST 16 bytes of cipher, edata2 = the rest

    AES (17/18): $krb5tgs$18$user$realm$*spn*$checksum$edata2
                  - user/realm bare, then a '*spn*' block in the MIDDLE
                  - checksum = LAST 12 bytes of cipher, edata2 = everything before

    Also tolerated: AES without the '*spn*' block (hashcat-native shape)
                    $krb5tgs$18$user$realm$checksum$edata2

Parsing strategy: edata2 and checksum never contain '$', so we peel them off
the RIGHT with rsplit. Whatever is left between the etype and the checksum is
the principal/SPN metadata, parsed flexibly — this makes placement of the
'*...*' block irrelevant.

No third-party deps. Structural validation only — it does NOT decrypt or crack.

--hashcat mode normalizes every VALID line to the bare, token-parser-safe form
    $krb5tgs$<etype>$<user>$<realm>$<checksum>$<edata2>
on stdout (diagnostics to stderr), so you can pipe straight into hashcat.
"""

import argparse
import re
import sys

ETYPE_INFO = {
    "17": {
        "name": "AES128-CTS-HMAC-SHA1-96",
        "hashcat_mode": 19600,
        "checksum_bytes": 12,   # 96-bit truncated HMAC-SHA1, tail of cipher
        "salted": True,
        "kdf_iters": 4096,
    },
    "18": {
        "name": "AES256-CTS-HMAC-SHA1-96",
        "hashcat_mode": 19700,
        "checksum_bytes": 12,   # 96-bit truncated HMAC-SHA1, tail of cipher
        "salted": True,
        "kdf_iters": 4096,
    },
    "23": {
        "name": "RC4-HMAC",
        "hashcat_mode": 13100,
        "checksum_bytes": 16,   # 128-bit HMAC-MD5, head of cipher
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
        self.spn = None
        self.checksum = None
        self.edata2 = None
        self.layout = None       # 'rc4-block' | 'aes-spn' | 'bare'
        self.errors = []
        self.warnings = []
        self.info = {}

    def fail(self, msg):
        self.ok = False
        self.errors.append(msg)


def _is_hex(s):
    return bool(s) and bool(HEX_RE.match(s))


def _parse_meta(meta, r):
    """Pull user/realm/spn out of the chunk between etype and checksum."""
    meta = meta.strip()

    if meta.startswith("*") and meta.endswith("*"):
        # RC4 layout: *user$realm$spn*
        r.layout = "rc4-block"
        inner = meta[1:-1]
        parts = inner.split("$")
        if len(parts) == 3:
            r.user, r.realm, r.spn = parts
        elif len(parts) == 2:
            r.user, r.realm = parts
        else:
            r.fail(f"Principal block has {len(parts)} '$'-parts; "
                   f"expected 2-3 (user/realm[/spn]).")
        return

    if "*" in meta:
        # AES layout: user$realm$*spn*
        r.layout = "aes-spn"
        m = re.match(r"^(.*?)\*([^*]*)\*\s*$", meta)
        if not m:
            r.fail("Malformed '*spn*' block in AES-layout hash.")
            return
        head, spn = m.group(1), m.group(2)
        r.spn = spn
        head_parts = [p for p in head.split("$") if p != ""]
        if len(head_parts) >= 2:
            r.user, r.realm = head_parts[0], head_parts[1]
        elif len(head_parts) == 1:
            r.user = head_parts[0]
            r.fail("AES-layout hash missing realm before '*spn*' block.")
        else:
            r.fail("AES-layout hash missing user/realm before '*spn*' block.")
        return

    # Bare layout: user$realm  (hashcat-native, no spn block)
    r.layout = "bare"
    parts = meta.split("$")
    if len(parts) == 2:
        r.user, r.realm = parts
    elif len(parts) == 1 and parts[0]:
        r.user = parts[0]
        r.fail("Hash missing realm field.")
    else:
        r.fail(f"Unexpected principal section: {len(parts)} '$'-parts.")


def parse_hash(raw):
    """Parse one hash line into a ParseResult. Structural checks only."""
    r = ParseResult()
    line = raw.strip()

    if not line.startswith("$krb5tgs$"):
        r.fail("Missing '$krb5tgs$' signature — not a TGS-REP Kerberoast hash.")
        return r

    body = line[len("$krb5tgs$"):]

    etype, sep, rest = body.partition("$")
    if not sep:
        r.fail("Truncated after signature; no etype field.")
        return r
    r.etype = etype
    if etype in ETYPE_INFO:
        r.info = dict(ETYPE_INFO[etype])
    else:
        r.fail(f"Unknown/unsupported etype '{etype}' (expected 17, 18, or 23).")

    # edata2 and checksum never contain '$' — peel them off the right.
    if rest.count("$") < 2:
        r.fail("Too few '$'-separated fields; expected "
               "...$checksum$edata2 at minimum.")
        return r

    meta, checksum, edata2 = rest.rsplit("$", 2)
    r.checksum, r.edata2 = checksum, edata2

    _parse_meta(meta, r)
    _validate_fields(r)
    return r


def _validate_fields(r):
    if not r.user:
        r.fail("Empty user/principal field.")
    if not r.realm:
        r.fail("Empty realm field.")
    if not r.checksum:
        r.fail("Empty checksum field.")
    if not r.edata2:
        r.fail("Empty edata2 (ciphertext) field.")

    if r.realm and r.realm != r.realm.upper():
        r.warnings.append(
            f"Realm '{r.realm}' is not uppercase. AES salt = "
            f"UPPERREALM+principal, so mixed case can break cracking."
        )

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

    if r.edata2:
        if not _is_hex(r.edata2):
            r.fail("edata2 contains non-hex characters.")
        elif len(r.edata2) % 2 != 0:
            r.fail(f"edata2 hex length {len(r.edata2)} is odd "
                   f"(not whole bytes).")
        else:
            ebytes = len(r.edata2) // 2
            if ebytes < 32:
                r.warnings.append(
                    f"edata2 is only {ebytes} bytes — suspiciously short "
                    f"for a real ticket enc-part; check for truncation."
                )
            r.info["edata2_bytes"] = ebytes


def to_hashcat(r):
    """Emit the hashcat-parseable form for a VALID hash.

    The required layout is ETYPE-DEPENDENT — verified against hashcat's own
    test modules (m13100 / m19600 / m19700):

      RC4 (23 / mode 13100): the token parser REQUIRES the principal block:
          $krb5tgs$23$*user$realm$spn*$checksum$edata2
        If no SPN was captured we fall back to the user as the spn so the
        '*...*' block is still well-formed.

      AES (17,18 / modes 19600,19700): the parser wants the BARE form, no
      asterisk block:
          $krb5tgs$<etype>$user$realm$checksum$edata2

    Returns None if the hash is not valid enough to reconstruct safely.
    """
    if not r.ok:
        return None
    if not (r.etype and r.user and r.realm and r.checksum and r.edata2):
        return None

    if r.etype == "23":
        spn = r.spn if r.spn else r.user
        return (f"$krb5tgs$23$*{r.user}${r.realm}${spn}*"
                f"${r.checksum}${r.edata2}")

    # AES etypes -> bare form
    return f"$krb5tgs${r.etype}${r.user}${r.realm}${r.checksum}${r.edata2}"


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
    if r.layout:
        lines.append(f"     layout:   {r.layout}")
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
    if r.etype in ETYPE_INFO:
        if r.info.get("salted"):
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
    ap.add_argument("--hashcat", action="store_true",
                    help="emit normalized, hashcat-parseable hashes to stdout "
                         "(bare '$krb5tgs$etype$user$realm$cksum$edata2', no "
                         "'*spn*' block) — one per VALID line; diagnostics go "
                         "to stderr. Pipe straight into hashcat or redirect to "
                         "a file.")
    args = ap.parse_args(argv)

    # In --hashcat mode, clean hashes go to stdout; everything human-readable
    # goes to stderr so a redirect/pipe captures only crackable lines.
    out = sys.stderr if args.hashcat else sys.stdout

    total = valid = invalid = emitted = 0
    for i, raw in enumerate(iter_input(args), 1):
        r = parse_hash(raw)
        total += 1
        if r.ok:
            valid += 1
        else:
            invalid += 1

        if args.hashcat:
            hc = to_hashcat(r)
            if hc:
                print(hc)              # stdout: the clean hash
                emitted += 1
            else:
                # surface why a line was skipped, to stderr
                print(format_report(r, raw, idx=i, verbose=args.verbose),
                      file=sys.stderr)
                print(file=sys.stderr)
            continue

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

    summary = f"--- {valid}/{total} valid, {invalid} invalid"
    if args.hashcat:
        summary += f", {emitted} emitted ---"
    else:
        summary += " ---"
    print(summary, file=out)
    return 0 if invalid == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
