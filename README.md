# guns.lol is a bio page service,
and, as every other popular service in the bio niche, it has a views counter.

this is just a cosmetic thing, nothing more than a counter. but people would kill for those numbers to be big.

## why does this PoW thing even matter in the first place?
well, people at guns.lol aren't dumb *(like i am!)*, so in order for a visit on someone's bio to count, inside of the `/api/analytics/record` request you **must** provide:
* a turnstile token,
* and a valid solve of their PoW captcha.

while i can't help you with solving turnstile.. i can help ya with solving PoW!

## so, how does guns.lol PoW work?
when you load someone's bio, the server stuffs a little `const _gs_sets = { ... }` blob into the HTML. four fields matter:
* `o09` - a 32-byte target hash *(shown as 64 hex chars)*
* `_n` - a random 32-char nonce
* `_org_ts` - well, it's a timestamp, duh!
* `_2xa` - a `base64url` blob that contains a 64-char hex seal template, except ~5 characters of it are blanked out. it also tells you which positions got blanked.

and your task (well, more like your browser's running task) is to figure out what those ~5 blanks should be, so that `SHA-256(filled_seal + _n + _org_ts) == bytes.fromhex(o09)`.
and how do you figure them out? by.. brute forcing it. yes, that's literally the whole point of "proof of work".

## soo, how do we solve it?
first, we get the thing we need to solve in the first place. this can pretty much do the job:
```python
from curl_cffi import requests
import re

def grab_tokens():
    session = requests.Session(impersonate="chrome124")
    response = session.get(f"https://guns.lol/hris", timeout=15)
    response.raise_for_status()

    html = response.text
    match = re.compile(r"const\s+_gs_sets\s*=\s*\{([^}]*)\}", re.DOTALL).search(html)
    if not match:
        raise RuntimeError("_gs_sets not found / CF challenge or layout change")
    body = match.group(1)

    values = {}
    for match in re.compile(r"""([_A-Za-z][_A-Za-z0-9]*)\s*:\s*(?:'([^']*)'|"([^"]*)")""").finditer(body):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        values[key] = val

    return {
        "o09":     values["o09"],
        "_n":      values["_n"],
        "_org_ts": values["_org_ts"],
        "_2xa":    values["_2xa"],
    }
```
anddd, we just did the easier part, congratulations! now, here comes the solver.

guns.lol's `_2xa` blob is a `base64url-encoded` string with the layout of:
```
[0..2]        magic bytes: 0xA1 0x40
[2]           dd  -- number of blanks (usually 5)
[3..3+dd]     positions where the blanks live in the 64-char seal
[..+dd]       a permutation (not needed for solving)
[..+8]        an 8-byte key (we DO need this for the submission tag)
[..+(64-dd)]  the template -- the 64-dd characters we already know
[last 8]      server MAC (server-side only, we don't touch it)
```

here's a little parser that does the job of reading the insides of `_2xa`:

```python
import base64

def parse_2xa(s: str):
    blob = base64.urlsafe_b64decode(s + "==")
    assert blob[:2] == b"\xa1\x40"
    dd = blob[2]
    positions = list(blob[3 : 3 + dd])
    key = blob[3 + 2*dd : 3 + 2*dd + 8]
    template = blob[3 + 2*dd + 8 : 3 + 2*dd + 8 + (64 - dd)]
    return dd, positions, key, template
```

andd, now we have a 64-byte seal with dd holes in it. we already know which positions are holes *(from parsing the blob)*. what we have to do is basically loop through all `16^dd` possible fillings, hash each, and stop when one matches.
```python
import hashlib

def solve(o09, _n, _org_ts, _2xa):
    dd, positions, key, template = parse_2xa(_2xa)
    target = bytes.fromhex(o09)
    suffix = (_n + _org_ts).encode()
    sorted_pos = sorted(positions)

    seal = bytearray(64)
    t = 0
    for i in range(64):
        if i in sorted_pos:
            seal[i] = 0 # to be filled
        else:
            seal[i] = template[t]; t += 1

    for n in range(16 ** dd):
        v = n
        for pos in sorted_pos:
            seal[pos] = b"0123456789abcdef"[v & 0xf]
            v >>= 4
        if hashlib.sha256(bytes(seal) + suffix).digest() == target:
            return bytes(seal), positions, key, target # success, yay!
```

you'd think this is the end. well, technically, it is - we cracked the PoW. but here's the thing: just returning the solved seal isn't enough. guns.lol also wants a **BLAKE3 tag** that proves you actually parsed `_2xa`, because it embeds the server's key inside it.
don't worry, it is also pretty simple to do:

```python
from blake3 import blake3

def build_oo(seal, positions, key, target, dd):
    # positions here is the ORIGINAL order straight out of _2xa
    solution_chars = bytes(seal[p] for p in positions)

    prefix = bytes([0x51, dd]) + solution_chars + b"\x01\x00\x00\x00"
    tag = blake3(prefix + key + target).digest()[:8]
    return base64.urlsafe_b64encode(prefix + tag).rstrip(b"=").decode()
```

and just like that - we've completed guns.lol's PoW! yay!

## BE AWARE!
this project is for **educational purposes** - to show the process of solving Proof-of-Work captchas. this **SHALL NOT** be used for anything rather than learning how guns.lol Proof of Work captcha works, as using it to bot views, or any action that involves their PoW captcha is prohibited by [guns.lol's terms of service](https://guns.lol/terms):
* Deploy, authorize, or benefit from automated scripts, bots, crawlers, or similar tools that interact with the Service without prior written permission.

any action taken against your account that may result from using code in this github repo is **entirely** your fault. you have been warned.
