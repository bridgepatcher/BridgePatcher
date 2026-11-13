#!/usr/bin/env python3
"""Find websites that imitate this project's name or its GitHub Pages site,
and open a tracking issue in this repository for each one."""

import base64
import concurrent.futures as cf
import datetime
import html
import io
import itertools
import json
import os
import re
import socket
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from typosquat_watch import (MAX_DIST, fold, get, lev, paginate, post, request, skeleton,  # noqa: E402
                             summary, variants)

ORIGINAL = os.environ["ORIGINAL_REPO"]
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
SITE_URL = os.environ.get("SITE_URL", "").strip()
KEYWORDS = os.environ.get("KEYWORDS", "").split()
CT_KEYWORDS = os.environ.get("CT_KEYWORDS", "").split()
TLDS = os.environ.get("TLDS", "com net org io app dev").split()
MARKERS = [fold(m.strip()) for m in os.environ.get("CONTENT_MARKERS", "").split("|") if m.strip()]
ALLOWLIST = {h.lower() for h in os.environ.get("ALLOWLIST", "").split()}
# Former names of the project (e.g. OpenCore-Legacy-Patcher-T2): a working website whose address
# contains one counts as a lookalike even if its page doesn't mention the project
FORMER_NAMES = os.environ.get("FORMER_NAMES", "").split()
# Words that lookalike download sites put around the name (get-oclp.com, oclp-download.net).
# They're added to the keywords as written, not to every typo of them.
AFFIXES = [a.lower() for a in os.environ.get("AFFIXES", "").split()]
# Hosting platforms where anyone can claim <name>.<platform> (oclp.netlify.app, oclp.itch.io).
# Those addresses share the platform's wildcard certificate, so they never show up in
# certificate-transparency logs or newly registered domain lists: they're checked directly.
PLATFORMS = [p.lower().lstrip(".") for p in os.environ.get("PLATFORMS", "").split()]
# Former official addresses of the project (e.g. oclp-t2.github.io). They no longer belong to it,
# so they are reported as soon as anything is published there again. While they're down
# (404 or no response) they're skipped. Their issues use their own marker (<host>#live), so a
# closed issue from an earlier check doesn't hide a site that goes live later.
FORMER_HOSTS = [h.lower() for h in os.environ.get("FORMER_HOSTS", "").split()]
FORMER_HOST_MARK = "former official address of this project, no longer ours"
# Known impersonation sites (full addresses, path included, e.g. a copycat fork's GitHub Pages
# project site). Like former addresses they're checked on every run, online or not: while they're
# down they're only listed in the run summary, and an issue is opened as soon as they serve a page.
KNOWN_SITES = os.environ.get("KNOWN_SITES", "").split()
KNOWN_SITE_MARK = "known impersonation site, on the watch list"
# Copycat repositories' websites: GitHub repos that present themselves as this project (found
# with REPO_QUERIES, plus direct forks of this repo) are checked for a website of their own,
# their homepage link and their GitHub Pages project site. Those sites are watched like
# KNOWN_SITES: listed while down, an issue as soon as one serves a page.
REPO_QUERIES = [q.strip() for q in os.environ.get("REPO_QUERIES", "").split("|") if q.strip()]
CHECK_FORKS = os.environ.get("CHECK_FORKS", "true").lower() == "true"
ALLOWLIST_REPOS = {r.lower() for r in os.environ.get("ALLOWLIST_REPOS", "").split()}
COPYCAT_MARK = "website of a copycat repository"
# Quick runs only check FORMER_HOSTS, KNOWN_SITES and copycat repositories' websites (no
# lookalike, certificate, registration or web search), so a site going live is noticed within hours
QUICK_RUN = os.environ.get("QUICK_RUN", "false").lower() == "true"
# Newly registered domains: how many past days of registrations to check, and the
# names to look for in them (compared without dots, dashes or underscores)
NRD_DAYS = int(os.environ.get("NRD_DAYS", "3"))
NRD_KEYWORDS = [re.sub(r"[^a-z0-9]", "", k.lower()) for k in os.environ.get("NRD_KEYWORDS", "").split()]
# Content farms: sites under any domain name that scrape this project's releases, issues
# and PRs, often with fake "official" Dortania branding and ad overlays. They're found
# through a web search API (Brave Search), since their domains look nothing like ours.
# Without BRAVE_SEARCH_API_KEY this part is skipped.
SEARCH_QUERIES = [q.strip() for q in os.environ.get("SEARCH_QUERIES", "").split("|") if q.strip()]
BRAVE_KEY = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
SEARCH_RESULTS = min(int(os.environ.get("SEARCH_RESULTS", "20")), 20)
# Forums, news and video sites that discuss the project legitimately; never flagged as farms
FARM_ALLOWLIST = {h.lower() for h in os.environ.get("FARM_ALLOWLIST", "").split()}
# Script and iframe sources of ad networks typical for scraped "download" pages
AD_NETWORKS = ("googlesyndication.com", "adsbygoogle", "doubleclick.net", "adservice.google",
               "propellerads", "popads.net", "popcash.net", "adsterra", "monetag", "a-ads.com",
               "hilltopads", "clickadu", "exoclick", "juicyads", "ezoic", "mediavine", "taboola",
               "outbrain", "revcontent", "mgid.com", "adcash", "onclickads", "galaksion")
# Text that an honest page about this fork would contain
DISCLAIMERS = ("not affiliated", "unofficial", "independent community fork", "nicht mit dortania",
               "nicht offiziell", "inoffiziell")
LABEL = "typosquat-site"
# Misattributing articles: news and blog posts (often machine-translated editions such as
# en.soydemac.com) that present this fork's T2 support as news about Dortania's OpenCore Legacy
# Patcher, without naming BridgePatcher or saying it's an unofficial fork. Found through news
# feeds (Bing News, Google News; no key needed) and, with BRAVE_SEARCH_API_KEY, web search.
NEWS_QUERIES = [q.strip() for q in os.environ.get("NEWS_QUERIES", "").split("|") if q.strip()]
# Bing/Google News editions to search, as language-COUNTRY (each costs two requests per query)
NEWS_MARKETS = os.environ.get("NEWS_MARKETS", "en-US").split()
ARTICLE_LABEL = "misattributed-article"
# News sites always searched (through their WordPress search) even when no feed lists them
NEWS_SITES = [h.lower() for h in os.environ.get("NEWS_SITES", "").split()]
# Language subdomains of translated editions (en.example.com); see edition_hosts()
EDITION_PREFIXES = os.environ.get("EDITION_PREFIXES", "en es de fr it pt br").split()
# Searched on WordPress news sites, through their REST API
SITE_SEARCHES = ["OpenCore Legacy Patcher", "OCLP T2"]
# The upstream project's names, as articles write them
OCLP_NAMES = re.compile(r"opencore[\s-]*legacy[\s-]*patcher|\boclp\b(?![\s-]*t2\b)")
T2_CHIP = re.compile(r"\bt2(?![0-9])")  # T2, T2s, T2-equipped
# Words that claim support or a new capability (English, Spanish, German, French, Italian, Portuguese)
SUPPORT_CLAIM = re.compile(
    r"(?<!un)support|(?<!in)compatib|now (?:works|runs)|\badds?\b|\bbrings?\b|expands?|extends?|unlocks?|"
    r"soport|admite|ampl[ií]a|llega|unterst[uü]tz|erweitert|bringt|prend en charge|prise en charge|"
    r"[ée]tend|ajoute|supporto|estende|aggiunge|suport|adiciona|amplia")
# Words that negate a claim or leave T2 Macs out; a sentence containing one doesn't count
# ("doesn't support T2", "schließt T2-Geräte aus", "excepto los Mac T2", "T2 Macs remain unsupported").
# Bare "unsupported" isn't one: "brings Tahoe to unsupported T2 Macs" is a claim.
EXCLUDED = re.compile(
    r"\bnot\b|n't\b|\bno\b(?!\s+mac)|\bwithout\b|\bexcept|\bexclud|\bnever\b|"
    r"\b(?:remains?|are|is|stays?|still|left)\s+unsupported|"
    r"\bnicht\b|\bkein|\bohne\b|\bau(?:ß|ss)er\b|ausgenommen|ausgeschlossen|schlie(?:ß|ss)t\b.*\baus\b|"
    r"\bsin\b|\bexcept[oa]\b|\bsalvo\b|\bexcluy|\bnunca\b|"
    r"\bsauf\b|\bsans\b|\bexclu|\bpas\b|\bne\b|"
    r"\bnon\b|\btranne\b|\beccetto\b|\bsenza\b|\besclu|"
    r"\bn[ãa]o\b|\bsem\b|\bexceto\b|\bexclui")
SENTENCE_END = re.compile(r"(?<=[.!?;])\s+|\s+[|•·–—]\s+")
# A negation shortly before a claim word ("doesn't support", "no es compatible", "nicht unterstützt")
NEGATED = re.compile(r"(?:\bnot\b|n't\b|\bno\b|\bwithout\b|\bnicht\b|\bkein\w*|\bsin\b|\bpas\b|"
                     r"\bnon\b|\bn[ãa]o\b|\bsem\b|\bnunca\b|\bnever\b)[^.!?]{0,25}$")
# Text that credits the fork correctly; an article containing any of these isn't flagged
CREDITS = ("bridgepatcher", "bridge patcher", "unofficial", "not official", "fork", "bifurcaci",
           "no oficial", "inoffiziell", "nicht offiziell", "non officiel", "non ufficiale", "não oficial",
           "nao oficial", "albert m", "opencore-legacy-patcher-t2", "opencore legacy patcher t2", "oclp-t2",
           "oclp t2")
# Earlier real-world case against the upstream project, linked in every issue as a reference
PRIOR_CASE = ("For a real example of how such a site operated and was taken down, see Dortania's "
              "write-up on opencorelegacypatcher.com: "
              "https://github.com/dortania/OpenCore-Legacy-Patcher/issues/1120")
MARKER = "<!-- typosquat-site:{} -->"
UA = f"Mozilla/5.0 (compatible; typosquat-site-watch; +https://github.com/{ORIGINAL})"
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
DOWNLOAD_EXT = re.compile(r"\.(dmg|pkg|zip|app|exe|iso)(\?|#|$)", re.I)
# A link or button also counts as a download when its label says so, even if the URL has
# no file extension (e.g. a "Download macOS" button pointing to a GitHub releases page,
# a file host or the site's own /download page)
DOWNLOAD_WORDS = re.compile(
    r"download|herunterladen|t[ée]l[ée]charger|descargar|scaricare|baixar|pobierz|indir|"
    r"скачать|завантажити|下载|下載|ダウンロード|다운로드", re.I)
DOWNLOAD_PATH = re.compile(r"/(?:releases|downloads?)(?:/|$)", re.I)
DOWNLOAD_ATTR = re.compile(r"(?:^|\s)download(?:\s*=|\s|/|$)", re.I)
CLICKABLE = re.compile(r"<(a|button)\b([^>]*)>(.*?)</\1\s*>", re.I | re.S)
URL_ATTR = re.compile(r"""\b(?:href|data-href|data-url|data-link|data-download|formaction)\s*=\s*(["'])(.*?)\1""",
                      re.I | re.S)
JS_URL = re.compile(r"""(?:location(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(|window\.open\s*\()\s*["'`]([^"'`]+)["'`]""",
                    re.I)
LABEL_ATTR = re.compile(r"""\b(?:title|aria-label|alt|class|id|value)\s*=\s*(["'])(.*?)\1""", re.I | re.S)
TAG = re.compile(r"<[^>]+>")

socket.setdefaulttimeout(10)


# --------------------------------------------------------------- network --

def resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, 443)})
    except (OSError, UnicodeError):
        return []


def fetch(url, limit=2_000_000):
    """GET a page without running anything. Returns (status, final_url, html)."""
    for ctx in (ssl.create_default_context(), ssl._create_unverified_context()):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                ctype = r.headers.get("Content-Type", "")
                body = r.read(limit) if ("html" in ctype or "text" in ctype) else b""
                return r.status, r.geturl(), body.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, url, ""
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLError):
                continue  # retry once without certificate verification
            break
        except Exception:
            break
    return None, url, ""


def fetch_json(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            # rdap.org and crt.sh rate-limit bursts: wait and retry instead of reporting "no data"
            if e.code not in (429, 502, 503, 504) or attempt == 3:
                raise
            wait = e.headers.get("retry-after")
            time.sleep(min(int(wait), 30) if wait and wait.isdigit() else 3 * (attempt + 1))


# ------------------------------------------------------------ discovery --

def site_info(owner, name):
    pages = get(f"/repos/{ORIGINAL}/pages") or {}
    url = SITE_URL or pages.get("html_url") or f"https://{owner}.github.io/{name}/"
    parts = urllib.parse.urlsplit(url)
    return url, parts.hostname.lower(), parts.path or "/"


# Latin letters that have a Cyrillic twin, for internationalized (IDN) lookalike domains
CYRILLIC_TWINS = {"a": "а", "c": "с", "e": "е", "i": "і", "j": "ј", "o": "о", "p": "р",
                  "s": "ѕ", "x": "х", "y": "у"}


def unpuny(host):
    """Show punycode labels (xn--...) the way browsers display them."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def homograph_variants(keyword):
    """The keyword with Cyrillic lookalike letters, encoded as punycode labels."""
    kw = keyword.lower()
    spelled = {kw[:i] + CYRILLIC_TWINS[c] + kw[i + 1:] for i, c in enumerate(kw) if c in CYRILLIC_TWINS}
    spelled.add("".join(CYRILLIC_TWINS.get(c, c) for c in kw))
    out = set()
    for v in spelled - {kw}:
        try:
            out.add(v.encode("idna").decode("ascii"))
        except UnicodeError:
            pass
    return out


def _flat(text):
    return re.sub(r"[^a-z0-9]", "", fold(text))


def former_name_in_host(host):
    """Former project names contained in a hostname (ignoring the TLD, separators and lookalike letters)."""
    flat = _flat("".join(unpuny(host).lower().split(".")[:-1]))
    return [n for n in FORMER_NAMES if _flat(n) and _flat(n) in flat]


def former_name_pages():
    """<former name>.github.io: GitHub Pages addresses anyone could claim with a former project name."""
    hosts = set()
    for n in FORMER_NAMES:
        for v in {n.lower(), n.lower().replace("-", "")}:
            if HOST_LABEL.match(v):
                hosts.add(f"{v}.github.io")
    return hosts


def _words(keyword):
    return [w for w in re.split(r"[-_.\s]+", keyword.lower()) if w]


def name_forms(keyword):
    """The keyword's words in every order, joined with and without dashes, each also as a plural:
    legacy-opencore-patcher, legacyopencorepatcher, opencorelegacypatchers, ... Typo variants
    alone miss these, because reordering words or adding a letter is more than two typos."""
    words = _words(keyword)
    orders = itertools.permutations(words) if len(words) <= 3 else [words]
    out = set()
    for order in orders:
        for sep in ("", "-"):
            v = sep.join(order)
            out.update((v, v + "s"))
    return {v for v in out if HOST_LABEL.match(v)}


def affixed(keyword):
    """The keyword with AFFIXES in front or behind: getoclp, oclp-download, ..."""
    words = _words(keyword)
    out = set()
    for base in {"".join(words), "-".join(words)}:
        for a in AFFIXES:
            for sep in ("", "-"):
                out.update((a + sep + base, base + sep + a))
    return {v for v in out if HOST_LABEL.match(v)}


def platform_of(host):
    """The hosting platform a host is a subdomain of (e.g. "netlify.app"), or ""."""
    return next((p for p in PLATFORMS if host.endswith("." + p)), "")


def domain_candidates(keywords):
    hosts = set()
    for kw in keywords:
        labels = {v for v in variants(kw) if HOST_LABEL.match(v)} | name_forms(kw) | affixed(kw)
        for v in labels | homograph_variants(kw):
            hosts.update(f"{v}.{tld}" for tld in TLDS)
        # Platform subdomains only for the name itself (GitHub account names: at most 39 characters)
        for v in name_forms(kw):
            hosts.update(f"{v}.{p}" for p in PLATFORMS if len(v) <= 39)
    return hosts


def ct_hosts(keyword):
    """Hostnames from certificate-transparency logs that contain the keyword."""
    q = urllib.parse.quote(f"%{keyword}%")
    url = f"https://crt.sh/?q={q}&output=json&exclude=expired&deduplicate=Y"
    for attempt in range(3):
        try:
            rows = fetch_json(url, timeout=90)
            names = set()
            for row in rows:
                for n in (row.get("name_value") or "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n and "@" not in n:
                        names.add(n)
            return names
        except Exception as e:
            print(f"  crt.sh attempt {attempt + 1} for '{keyword}' failed: {e}")
            time.sleep(15)
    print(f"::warning::Certificate-transparency lookup for '{keyword}' failed; skipped this run.")
    return set()


def github_pages_candidates(site_host, site_path):
    """Lookalike <user>.github.io accounts that actually exist."""
    if not site_host.endswith(".github.io"):
        return {}
    user = site_host.split(".")[0]
    found = {}
    for v in variants(user):
        if v != user and HOST_LABEL.match(v) and get(f"/users/{v}"):
            found[f"{v}.github.io"] = site_path
    return found


def nrd_domains(days):
    """Domains registered in the last `days` days, from WhoisDS's free daily lists."""
    domains = set()
    today = datetime.datetime.now(datetime.timezone.utc).date()
    for back in range(1, days + 1):
        day = (today - datetime.timedelta(days=back)).isoformat()
        token = base64.b64encode(f"{day}.zip".encode()).decode()
        url = f"https://whoisds.com/whois-database/newly-registered-domains/{token}/nrd"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=90) as r:
                data = r.read()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist():
                    domains.update(line.strip().lower()
                                   for line in z.read(name).decode("ascii", "ignore").split())
        except Exception as e:
            print(f"::warning::Newly registered domain list for {day} unavailable: {e}")
    print(f"{len(domains)} newly registered domains checked")
    return domains


def nrd_match(domain):
    """True if the domain's name contains, or is a near-miss of, one of NRD_KEYWORDS."""
    label = re.sub(r"[^a-z0-9]", "", fold(unpuny(domain).split(".")[0]))
    for kw in NRD_KEYWORDS:
        if kw in label:
            return True
        dist = MAX_DIST if len(kw) >= 8 else 1  # short names only allow one typo
        if abs(len(label) - len(kw)) <= dist and (
                skeleton(label) == skeleton(kw) or lev(label, kw) <= dist):
            return True
    return False


# ------------------------------------------------------------ inspection --

def split_address(address):
    """("host", "/path/") for a watched address given as a URL or as host[/path]."""
    parts = urllib.parse.urlsplit(address if "://" in address else f"https://{address}")
    return (parts.hostname or "").lower(), parts.path or "/"


def watch_key(host, path):
    """Issue key for a watched address; "<host>#live" for a site root, as for former hosts."""
    return f"{host}{path.rstrip('/')}#live".lower()


def inspect_watched(host, path, mark, repo=None, need_marker=False, report_down=False):
    """A FORMER_HOSTS, KNOWN_SITES or copycat repository address: reported whenever it serves
    a page (with need_marker, only if the page names the project). While it's down (an error
    status or no response) it's only reported with report_down, once, as an offline site
    (key <address>#down); it gets its own issue (<address>#live) when it goes live."""
    status, final, page = fetch(f"https://{host}{path}")
    if not status or status >= 400:
        print(f"Watched address {host}{path} is down ({status or 'no response'})")
        summary(f"- `{host}{path}` (watched" + (f", site of {repo}" if repo else "")
                + f"): down ({status or 'no response'})")
        if not report_down:
            return None
        return {
            "host": host, "url": f"https://{host}{path}", "status": status, "ips": resolve(host),
            "title": "", "markers": [mark], "download_hosts": [], "links_official": False,
            "new_registration": False, "down": True, "repo": repo,
            "key": watch_key(host, path).replace("#live", "#down"), "label": f"{host}{path.rstrip('/')}",
        }
    low = fold(page)
    if need_marker and not any(m in low for m in MARKERS):
        print(f"  {host}{path} ({repo}) is up but doesn't name the project; not reported")
        return None
    title = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
    return {
        "host": host, "url": final, "status": status, "ips": resolve(host),
        "title": re.sub(r"\s+", " ", html.unescape(title.group(1))).strip()[:150] if title else "",
        "markers": [mark] + [m for m in MARKERS if m in low],
        "download_hosts": sorted({describe_host(u) for u in download_links(page, final)}),
        "links_official": f"github.com/{ORIGINAL}".lower() in low,
        "new_registration": False, "key": watch_key(host, path),
        "label": f"{host}{path.rstrip('/')}", "repo": repo,
    }


def copycat_repos(original):
    """Repositories (other than ours and allowlisted ones) that may present themselves as
    this project: REPO_QUERIES search results, and direct forks of this repository."""
    our_owner = original.split("/")[0].lower()
    repos = {}
    for q in REPO_QUERIES:
        _, data, _ = request("GET", f"/search/repositories?q={urllib.parse.quote(q)}&per_page=100")
        time.sleep(2.2)  # search API allows 30 requests per minute
        for item in (data or {}).get("items", []):
            repos.setdefault(item["full_name"].lower(), item)
    if CHECK_FORKS:
        for item in paginate(f"/repos/{original}/forks?per_page=100&sort=newest"):
            repos.setdefault(item["full_name"].lower(), item)
    return {k: r for k, r in repos.items()
            if r["owner"]["login"].lower() != our_owner and k not in ALLOWLIST_REPOS}


def copycat_sites(repos, site_host):
    """{(host, path): (repo, own_pages)} for the websites copycat repositories point to: the
    homepage link and, if Pages is on, <owner>.github.io/<repo>/. own_pages is True for the
    repo's own Pages address, which counts whatever it shows; other homepages only count if
    they name the project (a fork's owner may link a personal site)."""
    sites = {}
    for full, r in sorted(repos.items()):
        owner, name = r["owner"]["login"].lower(), r["name"].lower()
        pages = f"{owner}.github.io"
        own = (pages, "/") if name == pages else (pages, f"/{name}/")
        home = (r.get("homepage") or "").strip()
        if home:
            host, path = split_address(home)
            if host and not allowed(host, site_host) and host not in ("github.com", "www.github.com"):
                is_own = host == pages and path.rstrip("/").lower() == own[1].rstrip("/")
                sites.setdefault((host, path), (r["full_name"], is_own))
        if r.get("has_pages"):
            sites.setdefault(own, (r["full_name"], True))
    return sites


def link_target(url, base):
    """Absolute URL of a link, or None for in-page, mail and script-only links."""
    url = html.unescape(url).strip()
    if not url or url.lower().startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    return urllib.parse.urljoin(base, url)


def describe_host(url):
    """Where a link leads: its host, plus the account for GitHub links."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "?").lower()
    if host in ("github.com", "www.github.com"):
        owner = parts.path.strip("/").split("/")[0]
        return f"github.com/{owner}" if owner else "github.com"
    return host


def download_links(page, base):
    """URLs of the links and buttons on a page that offer a download.

    A link counts if it points at an installer file, carries the `download`
    attribute, leads to a releases/download page, or is labelled as a download
    ("Download macOS", an icon with alt="Download", class="btn-download", ...),
    wherever it points to, GitHub included."""
    found = set()
    for _tag, attrs, inner in CLICKABLE.findall(page):
        urls = [u for _q, u in URL_ATTR.findall(attrs)] + JS_URL.findall(html.unescape(attrs))
        urls = [u for u in (link_target(u, base) for u in urls) if u]
        if not urls:
            continue
        label = " ".join([TAG.sub(" ", inner)] + [v for _q, v in LABEL_ATTR.findall(attrs + " " + inner)])
        labelled = bool(DOWNLOAD_WORDS.search(fold(html.unescape(label))) or DOWNLOAD_ATTR.search(attrs))
        for u in urls:
            if labelled or DOWNLOAD_EXT.search(u) or DOWNLOAD_PATH.search(urllib.parse.urlsplit(u).path):
                found.add(u)
    # Anything else on the page that points straight at an installer file
    for _q, u in URL_ATTR.findall(page):
        u = link_target(u, base)
        if u and DOWNLOAD_EXT.search(u):
            found.add(u)
    return found


def allowed(host, site_host):
    return host == site_host or any(host == a or host.endswith("." + a) for a in ALLOWLIST)


def inspect(host, path):
    ips = resolve(host)
    if not ips:
        return None
    status, final, page = fetch(f"https://{host}{path}")
    if not page:
        status, final, page = fetch(f"http://{host}{path}")
    if not page:
        return None
    low = fold(page)
    hits = [m for m in MARKERS if m in low]
    if not hits:
        former = former_name_in_host(host)
        if not former:
            return None  # resolves, but doesn't present itself as this project
        hits = [f"former project name in the address ({', '.join(former)})"]
    title = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
    dl_hosts = sorted({describe_host(u) for u in download_links(page, final)})
    return {
        "host": host, "url": final, "status": status, "ips": ips,
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:150] if title else "",
        "markers": hits, "download_hosts": dl_hosts,
        "links_official": f"github.com/{ORIGINAL}".lower() in low,
    }


# Registrant names that are only a privacy placeholder, not the real owner
REDACTED = re.compile(r"(?i)redact|privacy|private|protect|proxy|withheld|whois|not disclosed|"
                      r"masking|anonymi[sz]ed|gdpr|domains by|contact information|data restricted")


def rdap(host):
    """Registrar, abuse contact and registration date (best effort)."""
    domain = ".".join(host.split(".")[-2:])
    try:
        data = fetch_json(f"https://rdap.org/domain/{domain}")
    except Exception:
        return {}

    def vcard(entity, key):
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if item and item[0] == key:
                return item[3]
        return None

    info = {}
    for ent in data.get("entities", []):
        if "registrant" in ent.get("roles", []):
            who = vcard(ent, "org") or vcard(ent, "fn")
            if isinstance(who, list):
                who = " ".join(str(w) for w in who if w)
            if who and not REDACTED.search(str(who)):
                info["registrant"] = str(who).strip()
        if "registrar" in ent.get("roles", []):
            info["registrar"] = vcard(ent, "fn")
            for sub in ent.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    info["abuse"] = vcard(sub, "email")
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            info["registered"] = ev.get("eventDate", "")[:10]
    info["nameservers"] = sorted({(ns.get("ldhName") or "").lower().rstrip(".")
                                  for ns in data.get("nameservers", []) if ns.get("ldhName")})
    return info


# --------------------------------------------------------- content farms --

def brave_search(query):
    """Result URLs for one query from the Brave Search API."""
    q = urllib.parse.urlencode({"q": query, "count": SEARCH_RESULTS, "safesearch": "off"})
    req = urllib.request.Request(f"https://api.search.brave.com/res/v1/web/search?{q}", headers={
        "Accept": "application/json", "X-Subscription-Token": BRAVE_KEY, "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
    except Exception as e:
        print(f"::warning::Web search for '{query}' failed: {e}")
        return []
    return [res.get("url") for res in (data.get("web") or {}).get("results", []) if res.get("url")]


def farm_candidates(site_host):
    """One result URL per host from the web search, minus allowlisted hosts."""
    if not SEARCH_QUERIES:
        return {}
    if not BRAVE_KEY:
        print("::notice::BRAVE_SEARCH_API_KEY not set; content-farm search skipped.")
        return {}
    urls = {}
    for query in SEARCH_QUERIES:
        for url in brave_search(query):
            host = (urllib.parse.urlsplit(url).hostname or "").lower()
            if not host or allowed(host, site_host) or any(
                    host == a or host.endswith("." + a) for a in FARM_ALLOWLIST):
                continue
            urls.setdefault(host, url)
        time.sleep(1.2)  # free plan: about one request per second
    print(f"{len(urls)} hosts from web search to check for scraped content")
    return urls


def inspect_farm(host, url):
    """A search hit counts as a content farm when it shows this project's name AND at
    least one sign of misleading users: fake Dortania branding without a disclaimer,
    ad networks, or download buttons that lead away from GitHub."""
    status, final, page = fetch(url)
    if not page:
        return None
    low = fold(page)
    hits = [m for m in MARKERS if m in low]
    if not hits:
        return None
    ads = sorted({a for a in AD_NETWORKS if a in low})
    brand_claim = "dortania" in low and not any(d in low for d in DISCLAIMERS)
    dl_hosts = sorted({describe_host(u) for u in download_links(page, final)})
    foreign_dl = [h for h in dl_hosts if not (h.startswith("github.com") or h == host)]
    if not (ads or brand_claim or foreign_dl):
        return None  # mentions the project, but nothing points to deception
    title = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
    return {
        "host": host, "url": final, "status": status, "ips": resolve(host),
        "title": re.sub(r"\s+", " ", html.unescape(title.group(1))).strip()[:150] if title else "",
        "markers": hits, "download_hosts": dl_hosts,
        "links_official": f"github.com/{ORIGINAL}".lower() in low,
        "farm": True, "ads": ads, "brand_claim": brand_claim,
    }


# ------------------------------------------------ misattributing articles --

def main_content(page):
    """The article itself: the longest <article> block, else <main>, else the whole page.
    Keeps site menus, sidebars and related-post lists out of the judgement."""
    blocks = re.findall(r"<article\b[^>]*>(.*?)</article\s*>", page, re.I | re.S)
    if blocks:
        return max(blocks, key=len)
    m = re.search(r"<main\b[^>]*>(.*?)</main\s*>", page, re.I | re.S)
    return m.group(1) if m else page


def slugify(title):
    """The address slug blogs (WordPress and most others) make from a headline."""
    t = unicodedata.normalize("NFKD", fold(title))
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "-", t).strip("-")


def edition_hosts(host):
    """Other language editions of a news site: es.example.com -> example.com, www.example.com,
    en.example.com, ... Translated editions usually keep the original's address path."""
    labels = host.split(".")
    base = ".".join(labels[1:]) if len(labels) > 2 and labels[0] in EDITION_PREFIXES + ["www"] else host
    return ({base, f"www.{base}"} | {f"{p}.{base}" for p in EDITION_PREFIXES}) - {host}


def wp_search(host, query):
    """(url, title) of a WordPress site's posts matching a query, via its public REST API."""
    q = urllib.parse.urlencode({"search": query, "per_page": 20, "_fields": "link,title"})
    try:
        posts = fetch_json(f"https://{host}/wp-json/wp/v2/posts?{q}", timeout=20)
    except Exception:
        return []
    if not isinstance(posts, list):
        return []
    return [(p["link"], html.unescape(((p.get("title") or {}).get("rendered")) or ""))
            for p in posts if isinstance(p, dict) and p.get("link")]


def page_text(page):
    """Visible text of an HTML page, folded (scripts, styles and tags removed)."""
    page = re.sub(r"<(script|style|noscript)\b.*?</\1\s*>", " ", page, flags=re.I | re.S)
    return re.sub(r"\s+", " ", fold(html.unescape(TAG.sub(" ", page))))


def t2_claim(text, context=2):
    """The sentence in which `text` says OpenCore Legacy Patcher (gained) support for T2 Macs, or "":
    one that mentions T2 and a claim word and nothing that negates it or leaves T2 Macs out,
    with the project's name in it or in the `context` sentences around it."""
    sentences = [x for x in SENTENCE_END.split(text) if x.strip()]
    for i, sent in enumerate(sentences):
        if not T2_CHIP.search(sent) or EXCLUDED.search(sent):
            continue
        if not any(not NEGATED.search(sent[max(0, c.start() - 40):c.start()])
                   for c in SUPPORT_CLAIM.finditer(sent)):
            continue
        if OCLP_NAMES.search(" ".join(sentences[max(0, i - context):i + context + 1])):
            return sent.strip()
    return ""


def bing_news(query, market):
    """(url, title) pairs from Bing News' RSS feed; links carry the article URL in `url=`."""
    q = urllib.parse.urlencode({"q": query, "format": "rss", "mkt": market, "setlang": market.split("-")[0]})
    out = []
    try:
        req = urllib.request.Request(f"https://www.bing.com/news/search?{q}", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            root = ET.fromstring(r.read())
    except Exception as e:
        print(f"::warning::Bing News search for '{query}' ({market}) failed: {e}")
        return out
    for item in root.iter("item"):
        link = (item.findtext("link") or "").strip()
        real = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query).get("url", [link])[0]
        out.append((real, (item.findtext("title") or "").strip()))
    return out


def google_news(query, market):
    """(url, title, source host) triples from Google News' RSS feed. Its links are Google
    redirects that need JavaScript, so these items are judged by title and source only."""
    lang, country = (market.split("-") + ["US"])[:2]
    q = urllib.parse.urlencode({"q": query, "hl": market, "gl": country, "ceid": f"{country}:{lang}"})
    out = []
    try:
        req = urllib.request.Request(f"https://news.google.com/rss/search?{q}", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            root = ET.fromstring(r.read())
    except Exception as e:
        print(f"::warning::Google News search for '{query}' ({market}) failed: {e}")
        return out
    for item in root.iter("item"):
        src = item.find("source")
        host = (urllib.parse.urlsplit(src.get("url", "")).hostname or "").lower() if src is not None else ""
        title = (item.findtext("title") or "").strip()
        if src is not None and src.text and title.endswith(" - " + src.text.strip()):
            title = title[: -len(src.text.strip()) - 3]  # Google appends " - <site name>"
        out.append(((item.findtext("link") or "").strip(), title, host))
    return out


def article_candidates(site_host):
    """{host: (url, title, fetchable)} for news and search hits outside allowlisted sites."""
    found = {}

    def add(url, title, host=None, fetchable=True):
        host = (host or urllib.parse.urlsplit(url).hostname or "").lower()
        if not host or allowed(host, site_host) or any(host == a or host.endswith("." + a) for a in FARM_ALLOWLIST):
            return
        if host not in found or (fetchable and not found[host][2]):
            found[host] = (url, title, fetchable)

    for query in NEWS_QUERIES:
        for market in NEWS_MARKETS:
            for url, title in bing_news(query, market):
                add(url, title)
            for url, title, host in google_news(query, market):
                add(url, title, host, fetchable=False)
            time.sleep(1)
        if BRAVE_KEY:
            for url in brave_search(query):
                add(url, "")
            time.sleep(1.2)
    for host in NEWS_SITES:
        for query in SITE_SEARCHES:
            for url, title in wp_search(host, query):
                add(url, title)
    print(f"{len(found)} sites with news or search hits to check for misattribution")
    return found


def article_editions(hit, copycats, site_host):
    """Other language editions of a flagged article's site: the same address path on each
    edition host, and the edition's own WordPress search."""
    parts = urllib.parse.urlsplit(hit["url"])
    path = parts.path or "/"
    if (parts.hostname or "").lower() != hit["host"]:  # a Google News link: guess from the headline
        path = f"/{slugify(hit['title'])}/" if hit["title"] else "/"
    out = []
    for host in sorted(edition_hosts(hit["host"])):
        if allowed(host, site_host) or not resolve(host):
            continue
        tries = [(f"https://{host}{path}", "")] if path != "/" else []
        for query in SITE_SEARCHES:
            tries += wp_search(host, query)
        for url, title in tries:
            r = inspect_article(host, url, title, True, copycats)
            if r:
                r["edition_of"] = hit["host"]
                out.append(r)
                break
    return out


def inspect_article(host, url, title, fetchable, copycats):
    """An article that presents T2 support as OpenCore Legacy Patcher news without crediting
    this fork. Judged on the page when it can be fetched, otherwise on the headline."""
    status, final, page = fetch(url) if fetchable else (None, url, "")
    if not fetchable and title:
        # Google News only gives a headline: try the address blogs derive from it
        guess = f"https://{host}/{slugify(title)}/"
        g_status, g_final, g_page = fetch(guess)
        if g_page and g_status and g_status < 400 and slugify(title)[:40] in slugify(page_text(g_page)):
            status, final, page = g_status, g_final, g_page
    if page:
        m = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
        title = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip() if m else title
    text = page_text(main_content(page)) if page else ""
    head = fold(title)
    claim = t2_claim(head) or t2_claim(text)
    if not claim:
        return None
    if any(c in head or c in text for c in CREDITS):
        return None  # names the fork or says it's unofficial
    low = fold(page)
    linked = sorted({f"{o}/{n}" for o, n in re.findall(r"github\.com/([\w.-]+)/([\w.-]+)", low)})
    return {
        "host": host, "url": final, "status": status, "ips": resolve(host), "title": title[:200],
        "markers": [], "download_hosts": sorted({describe_host(u) for u in download_links(page, final)}) if page else [],
        "links_official": f"github.com/{ORIGINAL}".lower() in low,
        "article": True, "claim": claim[:400], "judged_on": "page" if page else "headline",
        "dortania": "dortania" in low or "dortania" in head,
        "copycat_links": [r for r in linked if r.lower() in copycats],
        "ads": sorted({a for a in AD_NETWORKS if a in low}),
        "key": f"article:{host}",
    }


def article_issue_body(r):
    shown = unpuny(r["host"])
    lines = [
        f"Found an article that presents T2 Mac support as news about OpenCore Legacy Patcher, without "
        f"saying it comes from this independent fork: **{shown}**",
        "",
        f"- **URL:** {r['url']}" + (f" (HTTP {r['status']})" if r["status"] else ""),
        f"- **Headline:** {r['title'] or '—'}",
    ] + ([f"- **Edition of:** {r['edition_of']} (same article in another language)"] if r.get("edition_of") else []) + [
        f"- **Judged on:** the {r['judged_on']}"
        + (" (the feed only gives a Google News link; open it to reach the article)" if r["judged_on"] == "headline" else ""),
        f"- **Passage:** > {r['claim']}",
        f"- **Mentions Dortania:** {'yes' if r['dortania'] else 'no'}",
        f"- **Links to the official repo:** {'yes' if r['links_official'] else 'no'}",
        f"- **Links to copycat repos:** {', '.join(r['copycat_links']) or 'none'}",
        f"- **Download links point to:** {', '.join(r['download_hosts']) or 'no download links'}",
        f"- **Ad networks:** {', '.join(r['ads']) or 'none found'}",
        "",
        "Articles like this make readers think Dortania's OpenCore Legacy Patcher supports T2 Macs, which "
        "sends them to the wrong project for downloads and support. It may simply be a news report that "
        "missed the distinction; please read it before acting.",
        "",
        "**If it misattributes the project:** ask the site's editors for a correction (it's BridgePatcher, an "
        f"independent fork at https://github.com/{ORIGINAL}, not Dortania's OpenCore Legacy Patcher). Translated "
        "editions such as `en.` subdomains are usually generated from the original-language article, so correcting "
        "that one fixes both. If it links to a copycat repo or foreign downloads, report those as well.",
        "",
        "Closing this issue marks the site as handled, and the workflow won't file it again.",
        "",
        MARKER.format(r["key"]),
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------- texts --

def farm_issue_body(r, reg):
    contact = f" ({reg['abuse']})" if reg.get("abuse") else ""
    signs = []
    if r["brand_claim"]:
        signs.append("mentions **Dortania** without saying this is an independent, unofficial fork "
                     "(possible fake official branding)")
    if r["ads"]:
        signs.append("loads ad networks: " + ", ".join(f"`{a}`" for a in r["ads"]))
    off = [h for h in r["download_hosts"] if not h.startswith("github.com")]
    if off:
        signs.append("download links lead away from GitHub: " + ", ".join(off))
    lines = [
        "Found a page that republishes content about this project and shows signs of misleading users: "
        f"**{r['host']}**",
        "",
        f"- **URL:** {r['url']} (HTTP {r['status']})" if r["status"] else f"- **URL:** {r['url']}",
        f"- **Page title:** {r['title'] or '—'}",
        f"- **Matched text:** {', '.join(f'`{m}`' for m in r['markers'])}",
        f"- **Links to the official repo:** {'yes' if r['links_official'] else 'no'}",
        f"- **Download links point to:** {', '.join(r['download_hosts']) or 'no download links'}",
        f"- **IP addresses:** {', '.join(r['ips']) or '—'}",
    ]
    if reg:
        lines += [
            f"- **Registrar:** {reg.get('registrar') or '—'}",
            f"- **Registrar abuse contact:** {reg.get('abuse') or '—'}",
            f"- **Registered:** {reg.get('registered') or '—'}",
        ]
    lines += ["", "**Signs found:**"] + [f"- {x}" for x in signs] + [
        "",
        "These checks are heuristics: a blog post or mirror can trip them too. Please look at the page first.",
        "",
        "**If it's a deceptive content farm:** if downloads on it are malicious, report it to "
        "[Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_badware/); "
        f"report fake branding or scraped content to the hosting provider and the registrar's abuse contact{contact}, "
        "and policy violations to the ad network it uses.",
        "",
        PRIOR_CASE,
        "",
        "Closing this issue marks the site as handled, and the workflow won't file it again.",
        "",
        MARKER.format(r.get("key", r["host"])),
    ]
    return "\n".join(lines)


def down_issue_body(r):
    status = f"HTTP {r['status']}" if r["status"] else "no response"
    if r["markers"][0] == KNOWN_SITE_MARK:
        why = "It's listed in `KNOWN_SITES` in `typosquat-sites.yml` as a known impersonation site."
    else:
        why = "It's the GitHub Pages address of a repository that presents itself as this project or is a fork of it."
    lines = [
        f"A copycat website is set up but offline for now: **{r['label']}**",
        "",
        why,
        "",
        f"- **URL:** {r['url']} ({status})",
    ] + ([f"- **Repository:** [`{r['repo']}`](https://github.com/{r['repo']})"] if r.get("repo") else []) + [
        f"- **Account:** [`{r['host'].split('.')[0]}`](https://github.com/{r['host'].split('.')[0]})"
        if r["host"].endswith(".github.io") else f"- **IP addresses:** {', '.join(r['ips']) or '—'}",
        "",
        "Nothing is published there right now, so there's nothing to report to GitHub or a host yet. "
        "The workflow checks it every 3 hours and opens a separate issue as soon as it serves a page.",
        "",
        "Closing this issue doesn't stop that check.",
        "",
        MARKER.format(r["key"]),
    ]
    return "\n".join(lines)


def issue_body(r, reg):
    if r["host"].endswith(".github.io"):
        account = r["host"].split(".")[0]
        where = f"GitHub Pages site of the account [`{account}`](https://github.com/{account})"
        action = ("Report the account or its Pages repository to GitHub "
                  "(**Report repository** / **Block or report** on their profile).")
    else:
        where = "independent domain"
        contact = f" ({reg['abuse']})" if reg.get("abuse") else ""
        action = ("If it impersonates the project, report it to the registrar's abuse contact"
                  f"{contact} and the hosting provider, and submit it to "
                  "[Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/).")
    shown = unpuny(r["host"])
    name = f"**{r['host']}**" + (f" (shown in browsers as **{shown}**)" if shown != r["host"] else "")
    if r["markers"] and r["markers"][0] == FORMER_HOST_MARK:
        intro = (f"Marked {name} as a typosquat: it was this project's official address before the rename "
                 "to BridgePatcher and no longer belongs to it. Anything published there now is not from "
                 "this project, even if it looks official.")
    elif r["markers"] and r["markers"][0] == COPYCAT_MARK:
        intro = (f"The website of a copycat repository is online: **{r.get('label', r['host'])}**\n\n"
                 f"It's the homepage or GitHub Pages site of [`{r['repo']}`](https://github.com/{r['repo']}), "
                 "a repository that presents itself as this project or is a fork of it. "
                 "It is not run by this project; check what it offers for download.")
    elif r["markers"] and r["markers"][0] == KNOWN_SITE_MARK:
        intro = (f"A known impersonation site is online: **{r.get('label', r['host'])}**\n\n"
                 "It's listed in `KNOWN_SITES` in `typosquat-sites.yml` and was down until now. "
                 "It is not run by this project; check what it offers for download.")
    elif r["markers"] and r["markers"][0].startswith("former project name"):
        intro = f"Found a website that uses this project's former name in its address: {name}"
    elif r["markers"]:
        intro = f"Found a website with a lookalike name that presents itself as this project: {name}"
    else:
        intro = (f"Found a newly registered domain with a lookalike name: {name}\n\n"
                 "It doesn't show project content yet. That's normal for a domain that was just registered; "
                 "impersonation sites are often set up a few days later, so it's worth keeping an eye on.")
    status = f"HTTP {r['status']}" if r["status"] else "no response yet"
    lines = [
        intro,
        "",
        f"- **URL:** {r['url']} ({status})",
        f"- **Newly registered:** {'yes, in the last ' + str(NRD_DAYS) + ' days' if r.get('new_registration') else 'not in the recent registration lists'}",
        f"- **Type:** {where}",
        f"- **Page title:** {r['title'] or '—'}",
        f"- **Matched text:** {', '.join(f'`{m}`' for m in r['markers']) or 'none yet'}",
        f"- **Links to the official repo:** {'yes' if r['links_official'] else 'no'}",
        f"- **Download links point to:** {', '.join(r['download_hosts']) or 'no download links'}",
        f"- **IP addresses:** {', '.join(r['ips']) or 'none (not resolving yet)'}",
    ]
    if reg:
        lines += [
            f"- **Registrar:** {reg.get('registrar') or '—'}",
            f"- **Registrar abuse contact:** {reg.get('abuse') or '—'}",
            f"- **Registered:** {reg.get('registered') or '—'}",
        ]
    lines += [
        "",
        "A matching name and project text don't prove bad intent; it may be a fan page or a mirror. "
        "Please check the site before acting.",
        "",
        f"**If it's an impersonation:** {action}",
        "",
        PRIOR_CASE,
        "",
        "Closing this issue marks the site as handled, and the workflow won't file it again.",
        "",
        MARKER.format(r.get("key", r["host"])),
    ]
    return "\n".join(lines)


# ------------------------------------------------------------------ main --

def main():
    repo = get(f"/repos/{ORIGINAL}")
    owner, name = repo["owner"]["login"], repo["name"]
    site_url, site_host, site_path = site_info(owner, name)
    keywords = KEYWORDS or [name.lower(), name.lower().replace("-", "")]

    summary(f"## Lookalike site scan for `{site_url}`" + (" (dry run)" if DRY_RUN else ""))

    targets, new_regs = {}, set()
    if QUICK_RUN:
        print("QUICK_RUN: checking only FORMER_HOSTS, KNOWN_SITES and copycat repositories' websites")
    else:
        targets = {h: "/" for h in domain_candidates(keywords)}
        for kw in CT_KEYWORDS:
            for h in ct_hosts(kw):
                targets.setdefault(h, "/")
        targets.update(github_pages_candidates(site_host, site_path))
        for h in former_name_pages():
            targets.setdefault(h, "/")
        new_regs = {d for d in nrd_domains(NRD_DAYS) if nrd_match(d)} if NRD_KEYWORDS else set()
        for h in new_regs:
            targets.setdefault(h, "/")
        targets = {h: p for h, p in targets.items() if not allowed(h, site_host)}
    print(f"{len(targets)} hostnames to check")

    with cf.ThreadPoolExecutor(max_workers=48) as ex:
        results = [r for r in ex.map(lambda hp: inspect(*hp), targets.items()) if r]

    # Content farms under unrelated domain names, found through web search
    farm_urls = {} if QUICK_RUN else {h: u for h, u in farm_candidates(site_host).items()
                                       if h not in {r["host"] for r in results}}
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        results += [r for r in ex.map(lambda hu: inspect_farm(*hu), farm_urls.items()) if r]

    # A lookalike domain registered in the last few days counts even before it shows
    # any content, so it's caught before it goes live.
    found_hosts = {r["host"] for r in results}
    for r in results:
        r["new_registration"] = r["host"] in new_regs
    for host in sorted(new_regs - found_hosts):
        if allowed(host, site_host):
            continue
        results.append({
            "host": host, "url": f"http://{host}/", "status": None, "ips": resolve(host),
            "title": "", "markers": [], "download_hosts": [], "links_official": False,
            "new_registration": True,
        })

    # Former official addresses and known impersonation sites are checked every run and
    # reported once something is published there (again). Their issues use their own key
    # (<address>#live), so a closed issue from an earlier finding doesn't hide them.
    watched = [(h, FORMER_HOST_MARK) for h in FORMER_HOSTS] + [(u, KNOWN_SITE_MARK) for u in KNOWN_SITES]
    by_host = {r["host"]: r for r in results if not r.get("farm")}
    for address, mark in watched:
        host, path = split_address(address)
        if not host:
            print(f"::warning::Can't read watched address '{address}'; skipped")
            continue
        if path == "/" and host in by_host:  # already found by the lookalike scan
            r = by_host[host]
            r["markers"].insert(0, mark)
            r["key"] = watch_key(host, path)
            continue
        r = inspect_watched(host, path, mark, report_down=mark == KNOWN_SITE_MARK)
        if r:
            results.append(r)

    # Websites of copycat repositories (their homepage link or GitHub Pages site)
    watched_keys = {watch_key(*split_address(a)) for a, _ in watched}
    repos = copycat_repos(ORIGINAL)

    # Articles presenting this fork's T2 support as OpenCore Legacy Patcher news (daily runs only)
    if not QUICK_RUN and NEWS_QUERIES:
        arts = article_candidates(site_host)
        with cf.ThreadPoolExecutor(max_workers=16) as ex:
            hits = [r for r in ex.map(lambda kv: inspect_article(kv[0], *kv[1], set(repos)), arts.items()) if r]
        # Translated editions (en.soydemac.com for soydemac.com) rarely show up in news feeds
        known = {r["host"] for r in hits}
        for hit in list(hits):
            for r in article_editions(hit, set(repos), site_host):
                if r["host"] not in known:
                    known.add(r["host"])
                    hits.append(r)
        results += hits
    all_sites = copycat_sites(repos, site_host)
    for r in results:  # a KNOWN_SITES entry that is also a copycat repo's site: name the repo
        if r.get("key") and not r.get("repo"):
            for hp, (repo, _own) in all_sites.items():
                if watch_key(*hp).split("#")[0] == r["key"].split("#")[0]:
                    r["repo"] = repo
    sites = {hp: v for hp, v in all_sites.items() if watch_key(*hp) not in watched_keys}
    print(f"{len(repos)} copycat repositories, {len(sites)} websites of theirs to check")
    by_key = {r.get("key", r["host"]): r for r in results}
    for (host, path), (repo, own_pages) in sites.items():
        key = watch_key(host, path)
        if key in by_key or (path == "/" and host in by_key):  # already found by the lookalike scan
            hit = by_key.get(key) or by_key[host]
            hit["markers"].insert(0, COPYCAT_MARK)
            hit.update(key=key, repo=repo)
            continue
        r = inspect_watched(host, path, COPYCAT_MARK, repo=repo, need_marker=not own_pages,
                            report_down=own_pages and host.endswith(".github.io"))
        if r:
            results.append(r)
            by_key[key] = r

    tracked = set()
    for label in (LABEL, ARTICLE_LABEL):
        for issue in paginate(f"/repos/{ORIGINAL}/issues?labels={label}&state=all&per_page=100"):
            m = re.search(r"<!-- typosquat-site:(\S+) -->", issue.get("body") or "")
            if m:
                tracked.add(m.group(1).lower())

    new = [r for r in sorted(results, key=lambda r: r["host"]) if r.get("key", r["host"]) not in tracked]
    if any(not r.get("article") for r in new) and not DRY_RUN:
        post(f"/repos/{ORIGINAL}/labels",
             {"name": LABEL, "color": "b60205", "description": "Website imitating this project"})
    if any(r.get("article") for r in new) and not DRY_RUN:
        post(f"/repos/{ORIGINAL}/labels", {"name": ARTICLE_LABEL, "color": "d93f0b",
                                           "description": "Article presenting this fork as Dortania's OCLP"})

    for r in new:
        if r.get("down"):
            summary(f"- **{r['label']}** — offline copycat site, watched until it goes live")
        elif r.get("article"):
            summary(f"- **{r['host']}** (article) — {r['title'] or 'no title'}; says: {r['claim'][:160]}")
        else:
            summary(f"- **{r.get('label', r['host'])}** — {r['title'] or 'no title'}; matched "
                    + (", ".join(f"`{m}`" for m in r["markers"]) or "nothing yet (newly registered)"))
        if DRY_RUN:
            continue
        if r.get("down"):
            issue = {"title": f"Copycat site (offline for now): {r['label']}", "body": down_issue_body(r),
                     "labels": [LABEL]}
        elif r.get("article"):
            issue = {"title": f"Misattributing article: {r['host']}", "body": article_issue_body(r),
                     "labels": [ARTICLE_LABEL]}
        else:
            reg = {} if r["host"].endswith(".github.io") else rdap(r["host"])
            farm = r.get("farm")
            issue = {
                "title": f"{'Content farm' if farm else 'Lookalike site'}: {r.get('label', r['host'])}",
                "body": farm_issue_body(r, reg) if farm else issue_body(r, reg),
                "labels": [LABEL],
            }
        status, _ = post(f"/repos/{ORIGINAL}/issues", issue)
        if status >= 300:
            print(f"::error::Could not open an issue for {r['host']} (HTTP {status})")
        time.sleep(3)

    summary(f"\n{len(new)} new lookalike sites or articles found ({len(results)} matching in total).")


if __name__ == "__main__":
    main()
