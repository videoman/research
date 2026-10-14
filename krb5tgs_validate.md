# krb5tgs_validate.py

Parse and validate Kerberos 5 **TGS-REP** (Kerberoast) hashes, then normalize them into hashcat-ready input. Pure stdlib, no third-party deps. Structural validation only — it does **not** decrypt or crack.

## Supported etypes / modes

| etype | Encryption | hashcat `-m` | checksum width | salted |
|------:|------------|:------------:|:--------------:|:------:|
| 23    | RC4-HMAC                  | 13100 | 16 bytes (head of cipher) | no  |
| 17    | AES128-CTS-HMAC-SHA1-96   | 19600 | 12 bytes (tail of cipher) | yes |
| 18    | AES256-CTS-HMAC-SHA1-96   | 19700 | 12 bytes (tail of cipher) | yes |

## Recognized input layouts

The parser peels `checksum` and `edata2` off the **right** (neither contains `$`), so the position of the `*...*` block doesn't matter. Three shapes are accepted:

- **`rc4-block`** — `$krb5tgs$23$*user$realm$spn*$cksum$edata2` (Impacket RC4)
- **`aes-spn`** — `$krb5tgs$18$user$realm$*spn*$cksum$edata2` (Impacket AES — the one with the SPN block in the middle)
- **`bare`** — `$krb5tgs$18$user$realm$cksum$edata2` (hashcat-native)

## Flags

| Flag | Description |
|------|-------------|
| `hash` (positional) | A single hash string to validate. |
| `-f, --file FILE` | File of hashes, one per line. Use `-` for stdin. |
| `-v, --verbose` | Print the full `edata2` instead of a 48-char preview. |
| `-q, --quiet` | Only print the summary count and any **invalid** lines. |
| `--hashcat` | Emit normalized, hashcat-parseable hashes to **stdout**; diagnostics go to **stderr**. Etype-aware (see below). |
| `--split PREFIX` | Write normalized valid hashes into per-mode files `PREFIX.<mode>.txt`. Dedups. Implies `--hashcat` normalization. |

Default (no output flag) prints a human-readable report per hash: etype, mode, layout, user, realm, spn, checksum/edata2 sizes, salt, plus warnings and errors.

## What gets validated

- **Signature** — must start with `$krb5tgs$`.
- **etype** — must be 17, 18, or 23; anything else fails.
- **Checksum width** — enforced per etype (12 bytes for AES, 16 for RC4). A 16-byte checksum on an etype-17/18 line is a hard fail.
- **Hex sanity** — both `checksum` and `edata2` must be valid, even-length hex.
- **edata2 size floor** — warns under 32 bytes (likely truncated).
- **Realm casing** — warns on non-uppercase realm, since the AES salt is `UPPERREALM + principal` and mixed case silently breaks cracking.

## Normalization (`--hashcat` / `--split`)

Output format is **etype-dependent**, matched against hashcat's own test modules (`m13100` / `m19600` / `m19700`):

- **RC4 (13100)** — the token parser **requires** the block:
  `$krb5tgs$23$*user$realm$spn*$cksum$edata2`
  (if no SPN was captured, the user is reused as the spn so the block stays well-formed)
- **AES (19600 / 19700)** — the parser wants the **bare** form, no asterisk block:
  `$krb5tgs$<etype>$user$realm$cksum$edata2`

The `*spn*` metadata is not part of the salt, so dropping it for AES is lossless for cracking.

### Stream separation

In `--hashcat` mode, clean hashes go to **stdout** and all diagnostics go to **stderr** — so a redirect or pipe captures only crackable lines:

```bash
python3 krb5tgs_validate.py -f roasted.txt --hashcat > crack.txt   # crack.txt stays clean
```

> Note: `--hashcat` does **not** dedup (a stream to stdout shouldn't silently drop lines). Dedup lives in `--split`.

## Usage examples

```bash
# Validate a single hash (human-readable report)
python3 krb5tgs_validate.py '$krb5tgs$18$svc$CORP.LOCAL$<cksum>$<edata2>'

# Validate a dump file
python3 krb5tgs_validate.py -f roasted.txt

# Only surface the broken lines
python3 krb5tgs_validate.py -f roasted.txt -q

# Pipe straight from Impacket, normalize, crack
GetUserSPNs.py dom/user -request 2>/dev/null \
  | python3 krb5tgs_validate.py -f - --hashcat \
  | tee >(hashcat -m 19700 - rockyou.txt)

# Split a mixed dump into per-mode files (dedups automatically)
python3 krb5tgs_validate.py -f roasted.txt --split crack
#   -> crack.13100.txt, crack.19600.txt, crack.19700.txt
#   each prints its own ready-to-run: hashcat -m <mode> <file> <wordlist>
```

## Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | Every line valid. |
| `1` | At least one line invalid. |
| `2` | No input provided. |

## Sources

- [hashcat example hashes (wiki)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [hashcat-example-hashes.md (master)](https://github.com/hashcat/hashcat/blob/master/docs/hashcat-example-hashes.md)
