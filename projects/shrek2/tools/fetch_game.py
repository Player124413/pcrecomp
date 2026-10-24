#!/usr/bin/env python3
"""Get `System/game.exe` out of a link, for the lift.

    python3 projects/shrek2/tools/fetch_game.py --url <link> --out game.exe

The link may point at:

  * **a zip archive** anywhere inside it -- a whole install (`Shrek 2/System/`),
    a dump of `System/`, or a single file.  `*/System/game.exe` is preferred and
    only that one member is extracted, so a 785 MB upload costs a 785 MB
    download and a 274 KB write, not a 785 MB unpack;
  * **game.exe itself** (a direct file link);
  * a **Hugging Face** file page (`blob/`, any repo or dataset repo) -- the
    `blob/` in the URL is rewritten to `resolve/`, which is the raw file, and
    `HF_TOKEN` is used when the repo is private or gated;
  * a **Google Drive** share link (`/file/d/<id>/view`, `open?id=<id>`,
    `uc?id=<id>`, ...) -- including the "this file is too large to scan for
    viruses" interstitial, which is a form, not the file.

Only the standard library is used, so this works in a bare `python3` on the CI
runner without installing anything.

The target the lift was built against is read from `../config/game.json`; the
result is compared against it and reported.  A mismatch is not fatal here (the
driver owns that check, and `--any-game` exists), but it is what the person who
picked the link needs to see first.

Exit status: 0 wrote `--out`; 1 the link did not yield a game.exe; 2 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

USER_AGENT = ("Mozilla/5.0 (compatible; pcrecomp-shrek2-fetch/1.0; "
              "+https://github.com/Player124413/pcrecomp)")

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "..", "config", "game.json")

PE_MAGIC = b"MZ"
ZIP_MAGIC = b"PK\x03\x04"


# --------------------------------------------------------------------------
# URL normalisation
# --------------------------------------------------------------------------

def _drive_id(url: str):
    """The file id in any of Google Drive's share-link shapes, or None."""
    p = urllib.parse.urlparse(url)
    host = p.netloc.lower()
    if host not in ("drive.google.com", "docs.google.com",
                    "drive.usercontent.google.com"):
        return None
    q = urllib.parse.parse_qs(p.query)
    if "id" in q and q["id"]:
        return q["id"][0]
    m = re.search(r"/file/d/([A-Za-z0-9_-]{10,})", p.path)
    if m:
        return m.group(1)
    m = re.search(r"/d/([A-Za-z0-9_-]{10,})", p.path)
    if m:
        return m.group(1)
    return None


def normalise(url: str):
    """(kind, url) where kind is 'drive', 'huggingface' or 'direct'.

    A link a person copied from a browser tab is a *page*; what we need is the
    bytes behind it.  This is the whole translation table, in one place:
    """
    p = urllib.parse.urlparse(url)
    host = p.netloc.lower()

    fid = _drive_id(url)
    if fid:
        return "drive", fid

    if host in ("huggingface.co", "hf.co", "www.huggingface.co"):
        # /<user>/<repo>/blob/<rev>/<path>  ->  /resolve/<rev>/<path>
        # /datasets/<user>/<repo>/blob/...  ->  same, with datasets/ kept
        path = p.path
        path = re.sub(r"/(blob|raw)/", "/resolve/", path, count=1)
        if "/resolve/" not in path:
            # A repo page, not a file.  Say so now instead of downloading HTML.
            return "huggingface-page", url
        q = p.query
        if "download=true" in q:
            q = ""
        return "huggingface", urllib.parse.urlunparse(
            (p.scheme or "https", p.netloc, path, p.params, q, p.fragment))

    return "direct", url


def gdrive_url(fid: str) -> str:
    return ("https://drive.google.com/uc?export=download&id="
            + urllib.parse.quote(fid, safe=""))


# --------------------------------------------------------------------------
# Downloading
# --------------------------------------------------------------------------

class Fetcher:
    def __init__(self, hf_token: str = ""):
        self.hf_token = hf_token
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def _request(self, url: str, extra_headers=None):
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if self.hf_token and _is_hf(url):
            headers["Authorization"] = "Bearer " + self.hf_token
        if extra_headers:
            headers.update(extra_headers)
        return urllib.request.Request(url, headers=headers)

    def open(self, url: str):
        return self.opener.open(self._request(url), timeout=120)

    def stream_to(self, url: str, out_path: str, max_hops: int = 4) -> str:
        """Save the bytes behind `url` to `out_path`; return a short description.

        Follows Google Drive's interstitial: a big file comes back as an HTML
        page carrying a form (`action=...`, `id`, `export`, `confirm`, `uuid`)
        whose submission is the real download.  Any other HTML response is an
        error page -- a login wall, a quota message, a wrong id -- and is
        reported with its own words rather than as "not a zip".
        """
        url_ = url
        for hop in range(max_hops):
            with self.open(url_) as r:
                ctype = (r.headers.get("Content-Type") or "").lower()
                first = r.read(4)
                is_binary = first[:2] == PE_MAGIC or first[:4] == ZIP_MAGIC
                if is_binary or "html" not in ctype:
                    self._save(r, first, out_path)
                    return f"{url_} ({_mb(os.path.getsize(out_path))})"

                body = (first + r.read()).decode("utf-8", "replace")
                nxt = _drive_form_target(body, url_)
                if not nxt:
                    snippet = " ".join(re.sub(r"<[^>]+>", " ", body).split())[:300]
                    hint = ""
                    if "sign in" in body.lower() or "accounts.google.com" in body:
                        hint = (" -- the link requires a Google login; share it as "
                                "'anyone with the link'")
                    raise SystemExit(
                        f"the link returned an HTML page, not a file{hint}.\n"
                        f"  page says: {snippet}")
                print(f"[fetch] follow the download form -> {nxt[:120]}",
                      file=sys.stderr)
                url_ = nxt
        raise SystemExit("too many HTML redirects; the link is a page, not a file")

    @staticmethod
    def _save(response, first: bytes, out_path: str) -> None:
        tmp = out_path + ".part"
        with open(tmp, "wb") as f:
            f.write(first)
            shutil.copyfileobj(response, f, length=1 << 20)
        os.replace(tmp, out_path)


def _is_hf(url: str) -> bool:
    h = urllib.parse.urlparse(url).netloc.lower()
    return h in ("huggingface.co", "hf.co", "www.huggingface.co",
                 "cdn-lfs.huggingface.co", "cdn-lfs.hf.co")


def _drive_form_target(html: str, base: str):
    """The URL a Google Drive 'file too large to scan' page submits to."""
    m = re.search(r"<form[^>]*\baction=\"([^\"]+)\"", html, re.I)
    if not m:
        return None
    action = m.group(1).replace("&amp;", "&")
    fields = {}
    for name, value in re.findall(
            r"<input[^>]*\bname=\"([^\"]+)\"[^>]*\bvalue=\"([^\"]*)\"", html, re.I):
        fields[name] = value.replace("&amp;", "&")
    if not fields.get("id"):
        m2 = re.search(r"[?&]id=([A-Za-z0-9_-]+)", base)
        if m2:
            fields["id"] = m2.group(1)
    fields.setdefault("export", "download")
    fields.setdefault("confirm", "t")
    if not fields.get("id"):
        return None
    action = urllib.parse.urljoin(base, action)      # the form may say "/download"
    sep = "&" if urllib.parse.urlparse(action).query else "?"
    return action + sep + urllib.parse.urlencode(fields)


# --------------------------------------------------------------------------
# Archives
# --------------------------------------------------------------------------

def game_member(zf: zipfile.ZipFile, want: str = "game.exe"):
    """The member to extract, or None.

    Prefer the real thing: `<something>/System/game.exe`, then any
    `System/game.exe`, then a bare `game.exe`, then whatever else has that
    name.  An install archive is the common case, and it also contains
    `game.ini`, `game.log` and so on, hence the exact-name match.
    """
    names = [n for n in zf.namelist() if not n.endswith("/")]
    hits = [n for n in names if n.rsplit("/", 1)[-1].lower() == want]
    if not hits:
        return None

    def rank(n: str):
        low = n.lower()
        depth = low.count("/")
        return (
            0 if low.endswith("system/" + want) and depth >= 1 else
            1 if low.endswith("system/" + want) else
            2 if low.endswith("/" + want) else
            3,
            depth, len(n),
        )

    return sorted(hits, key=rank)[0]


def is_zip(path: str) -> bool:
    with open(path, "rb") as f:
        return f.read(4) == ZIP_MAGIC


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def describe(path: str) -> dict:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return {"size": n, "sha256": h.hexdigest()}


def compare_with_config(report: dict) -> None:
    try:
        with open(CONFIG) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        return
    size, sha = cfg.get("size"), cfg.get("sha256")
    if size == report["size"] and sha == report["sha256"]:
        print(f"[fetch] this is the binary the lift was built against "
              f"({size:,} bytes, sha256 {sha[:16]}...)")
        return
    print(f"[fetch] WARNING: not the binary this project was built against\n"
          f"[fetch]   expected {size:,} bytes, sha256 {str(sha)[:16]}...\n"
          f"[fetch]   got      {report['size']:,} bytes, sha256 {report['sha256'][:16]}...\n"
          f"[fetch] The driver will refuse it unless --any-game is passed.  That is\n"
          f"[fetch] correct for a different release/patch of the game: the lift is\n"
          f"[fetch] made from one exact image (offsets, vtables, entry point).",
          file=sys.stderr)


# --------------------------------------------------------------------------

def _mb(n: int) -> str:
    return f"{n / 1e6:.1f} MB"


def selftest() -> int:
    """Everything that can be checked without the network, checked."""
    import struct
    import tempfile

    ok = 0

    def want(got, expected, what):
        nonlocal ok
        assert got == expected, f"{what}: {got!r} != {expected!r}"
        ok += 1

    want(normalise("https://huggingface.co/u/r/blob/main/g.zip")[0], "huggingface", "hf kind")
    want(normalise("https://huggingface.co/u/r/blob/main/g.zip")[1],
         "https://huggingface.co/u/r/resolve/main/g.zip", "hf blob->resolve")
    want(normalise("https://huggingface.co/u/r")[0], "huggingface-page", "hf repo page")
    for link in ("https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz12345/view?usp=sharing",
                 "https://drive.google.com/open?id=1AbCdEfGhIjKlMnOpQrStUvWxYz12345",
                 "https://drive.google.com/uc?id=1AbCdEfGhIjKlMnOpQrStUvWxYz12345&export=download"):
        want(normalise(link), ("drive", "1AbCdEfGhIjKlMnOpQrStUvWxYz12345"), "drive id")
    want(normalise("https://example.com/a.zip"), ("direct", "https://example.com/a.zip"), "direct")

    form = ('<form action="/download"><input name="id" value="abc">'
            '<input name="confirm" value="t"></form>')
    want(_drive_form_target(form, "https://drive.google.com/uc?id=abc"),
         "https://drive.google.com/download?id=abc&confirm=t&export=download", "form target")
    want(_drive_form_target("<html>sign in</html>", "https://drive.google.com/uc?id=abc"),
         None, "login wall")

    pe = b"MZ" + b"\0" * 0x3a + struct.pack("<I", 0x40) + b"PE\0\0" + b"\0" * 32
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "install.zip")
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("game.exe", b"MZ bare")                 # present, but not the one
            z.writestr("Shrek 2/System/game.exe", pe)
            z.writestr("Shrek 2/System/game.ini", "[x]")
        with zipfile.ZipFile(zip_path) as z:
            want(game_member(z), "Shrek 2/System/game.exe", "member ranking")
        out = os.path.join(tmp, "game.exe")
        want(main(["--url", "file://" + zip_path, "--out", out]), 0, "file:// zip")
        with open(out, "rb") as f:
            want(f.read(), pe, "extracted bytes")

    print(f"[fetch] selftest: {ok} checks ok")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", help="link to game.exe or a zip of it")
    ap.add_argument("--out", help="where to write game.exe")
    ap.add_argument("--selftest", action="store_true",
                    help="check the URL handling and the archive extraction offline")
    ap.add_argument("--keep-archive", action="store_true",
                    help="keep the downloaded zip next to --out (.zip)")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.url or not args.out:
        ap.error("--url and --out are required (or --selftest)")

    kind, url = normalise(args.url.strip())
    if kind == "huggingface-page":
        print("[fetch] that is a Hugging Face repo page, not a file. Open the file\n"
              "[fetch] (e.g. game.zip) and copy the link from its 'blob' or\n"
              "[fetch] 'resolve' URL.", file=sys.stderr)
        return 1
    if kind == "drive":
        print(f"[fetch] Google Drive file {url}", file=sys.stderr)
        url = gdrive_url(url)
    elif kind == "huggingface":
        print(f"[fetch] Hugging Face: {url}", file=sys.stderr)
    else:
        print(f"[fetch] direct: {url}", file=sys.stderr)

    fetcher = Fetcher(hf_token=os.environ.get("HF_TOKEN", ""))
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="shrek2-fetch-") as tmp:
        blob = os.path.join(tmp, "download.bin")
        try:
            where = fetcher.stream_to(url, blob)
        except urllib.error.HTTPError as e:
            print(f"[fetch] HTTP {e.code} {e.reason} for {url}", file=sys.stderr)
            if e.code in (401, 403):
                print("[fetch] 401/403 is a permission problem: for Google Drive\n"
                      "[fetch] set the file to 'anyone with the link', for Hugging Face\n"
                      "[fetch] make the repo public or add an HF_TOKEN secret.",
                      file=sys.stderr)
            return 1
        except urllib.error.URLError as e:
            print(f"[fetch] cannot reach {url}: {e.reason}", file=sys.stderr)
            return 1
        print(f"[fetch] downloaded {where}", file=sys.stderr)

        if is_zip(blob):
            with zipfile.ZipFile(blob) as zf:
                member = game_member(zf)
                if member is None:
                    listing = ", ".join(zf.namelist()[:8]) or "(empty)"
                    print(f"[fetch] the zip holds no game.exe.  First entries: {listing}",
                          file=sys.stderr)
                    return 1
                print(f"[fetch] archive member: {member} "
                      f"({_mb(zf.getinfo(member).file_size)} unpacked)", file=sys.stderr)
                with zf.open(member) as src, open(args.out, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=1 << 20)
            if args.keep_archive:
                shutil.copyfile(blob, args.out + ".zip")
        else:
            with open(blob, "rb") as f:
                magic = f.read(2)
            if magic != PE_MAGIC:
                with open(blob, "rb") as f:
                    head = f.read(16)
                print("[fetch] what came back is not a zip and not a Windows exe.\n"
                      "[fetch] (Wrong link?  A folder link instead of a file link?)\n"
                      f"[fetch] first bytes: {head!r}",
                      file=sys.stderr)
                return 1
            shutil.copyfile(blob, args.out)

    report = describe(args.out)
    print(f"[fetch] wrote {args.out}: {report['size']:,} bytes, "
          f"sha256 {report['sha256']}")
    compare_with_config(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
