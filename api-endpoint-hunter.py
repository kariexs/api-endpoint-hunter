import asyncio
import aiohttp
import argparse
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin, urlparse
import sys
import time
import csv

try:
    from fpdf import FPDF
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

API_PARAM_HINTS = [
    "token", "key", "auth", "id", "user", "email", "pass", "search", "session", "access", "refresh"
]

ASCII_BANNER = """
\033[1;36m
███████╗██╗   ██╗ █████╗  █████╗  ██████╗ ███████╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝
███████╗ ╚████╔╝ ███████║██║  ██║██║   ██║█████╗  ███████╗
╚════██║  ╚██╔╝  ██╔══██║██║  ██║██║   ██║██╔══╝  ╚════██║
███████║   ██║   ██║  ██║╚█████╔╝╚██████╔╝███████╗███████║
╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚════╝  ╚═════╝ ╚══════╝╚══════╝

   \033[1;32mAI-Powered API Endpoint Hunter\033[0m
"""

COMMON_SENSITIVE_PATHS = [
    "/admin", "/admin/login", "/admin/dashboard", "/admin/config",
    "/debug", "/debug/info", "/debug/vars", "/debug/pprof",
    "/config", "/config.json", "/config.js", "/config.php", "/config.yml",
    "/configuration", "/conf/config.yaml", "/.env", "/.env.local",
    "/.git/config", "/.gitignore", "/.htaccess", "/.htpasswd",
    "/phpinfo.php", "/.well-known/security.txt", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association", "/.well-known/openid-configuration",
    "/.well-known/change-password", "/backup.zip", "/db.sql", "/database.sql",
    "/test.php", "/staging", "/prod", "/private", "/logs/error.log", "/logs/access.log"
]

def unique(seq):
    seen = set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            yield x

def filter_probable_endpoints(urls):
    filtered = []
    for url in urls:
        parsed = urlparse(url)
        path = parsed.path
        if re.match(r'.*\.(js|css|jpg|jpeg|png|svg|ico|woff|woff2|ttf|eot|map|webmanifest)$', path):
            continue
        if any(x in path for x in ["/chunks/", "/static/", "/main."]):
            continue
        if re.search(r'(webpack|manifest|polyfill|data-)', path):
            continue
        if len(path.strip("/")) <= 2:
            continue
        if re.search(r'/api|/auth|/v\d+|/users|/token|/search|/login|/signup|/graphql|/session', path, re.I):
            filtered.append(url)
            continue
        if any(param in parsed.query.lower() for param in API_PARAM_HINTS):
            filtered.append(url)
            continue
        if path.count("/") >= 2 and len(path) > 8:
            filtered.append(url)
            continue
    return list(unique(filtered))

ENDPOINT_PATTERNS = [
    r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]',
    r'axios\.\w+\s*\(\s*[\'"]([^\'"]+)[\'"]',
    r'\.open\s*\(\s*[\'"](GET|POST|PUT|DELETE|OPTIONS)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]',
    r'\$.ajax\s*\(\s*{[^}]*url\s*:\s*[\'"]([^\'"]+)[\'"]',
    r'\$http\.\w+\s*\(\s*[\'"]([^\'"]+)[\'"]',
    r'url\s*:\s*[\'"]([^\'"]+/api[^\'"]*)[\'"]',
    r'fetch\s*\(\s*\`([^\`]+)\`',
    r'axios\.\w+\s*\(\s*\`([^\`]+)\`',
    r'\.open\s*\(\s*[\'"](GET|POST|PUT|DELETE|OPTIONS)[\'"]\s*,\s*\`([^\`]+)\`',
    r'url\s*:\s*\`([^\`]+)\`',
]

def extract_endpoints_from_js(js_code, base_url):
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, js_code, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                url = match[-1]
            else:
                url = match
            url = url.strip('`"\' ')
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = urljoin(base_url, url)
            elif url.startswith("http"):
                pass
            else:
                url = urljoin(base_url, "/" + url)
            endpoints.add(url)
    return endpoints

def find_js_files(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    js_files = set()
    for script in soup.find_all('script'):
        src = script.get('src')
        if src:
            if src.startswith("data:"):
                continue
            js_url = urljoin(base_url, src)
            js_files.add(js_url)
        else:
            if script.string and len(script.string) > 100:
                js_files.add(("inline", script.string))
    return js_files

async def fetch_page(session, url):
    try:
        async with session.get(url, timeout=session.timeout) as response:
            response.raise_for_status()
            return await response.text()
    except Exception:
        return None

async def check_endpoint_status(session, url, method="GET", headers=None):
    try:
        async with session.request(method, url, timeout=session.timeout, headers=headers) as response:
            return response.status, response.reason
    except Exception:
        return None, "Unreachable"

def extract_context_parameters(url):
    params = {}
    q = urlparse(url).query
    for k in API_PARAM_HINTS:
        m = re.search(rf'{k}=([^&]+)', q, re.I)
        if m:
            params[k] = m.group(1)
    return params

def export_txt(endpoints, fname):
    with open(fname, "w", encoding="utf-8") as f:
        for ep in endpoints:
            f.write(ep['url'] + "\n")

def export_csv(endpoints, fname):
    with open(fname, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "status", "reason", "params", "sensitive"])
        writer.writeheader()
        for ep in endpoints:
            writer.writerow(ep)

def export_pdf(endpoints, fname):
    if not PDF_SUPPORT:
        print("PDF support requires: pip install fpdf")
        return
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt="API Endpoint Hunter Results", ln=True, align="L")
    for ep in endpoints:
        line = f"{ep['url']} [{ep['status']}] ({ep['reason']}) Params: {ep['params']}{' [SENSITIVE]' if ep['sensitive'] else ''}"
        pdf.cell(200, 8, txt=line, ln=True, align="L")
    pdf.output(fname)

async def scan_sensitive_paths(session, base_url, method, headers):
    found = []
    tasks = []
    for path in COMMON_SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        tasks.append(check_endpoint_status(session, url, method, headers))
    results = await asyncio.gather(*tasks)
    for idx, (status, reason) in enumerate(results):
        url = urljoin(base_url, COMMON_SENSITIVE_PATHS[idx])
        if status and int(status) < 500:
            found.append(url)
    return found

async def analyze_endpoints(endpoints, max_concurrency, delay, method, headers, timeout):
    semaphore = asyncio.Semaphore(max_concurrency)
    async def check(ep):
        async with semaphore:
            await asyncio.sleep(delay)
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                status, reason = await check_endpoint_status(session, ep['url'], method, headers)
                ep['status'] = status
                ep['reason'] = reason
                return ep
    coros = [check(ep) for ep in endpoints]
    return await asyncio.gather(*coros)

async def scan_all(args):
    print(ASCII_BANNER)
    start_time = time.time()
    base_url = args.target
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
    timeout = args.timeout
    all_eps = set()
    async with aiohttp.ClientSession(headers={'User-Agent': 'Mozilla/5.0 (AIBugBounty/5.0)'}, timeout=aiohttp.ClientTimeout(total=timeout)) as session:
        html = await fetch_page(session, base_url)
        js_sources = find_js_files(html, base_url) if html else set()
        for js in js_sources:
            js_content = None
            if isinstance(js, tuple) and js[0] == "inline":
                js_content = js[1]
            else:
                js_content = await fetch_page(session, js)
            if js_content:
                eps = extract_endpoints_from_js(js_content, base_url)
                all_eps.update(eps)
        all_eps = filter_probable_endpoints(all_eps)
        robots_txt = await fetch_page(session, urljoin(base_url, "/robots.txt"))
        robots_eps = [urljoin(base_url, p.split(":")[1].strip())
                      for p in robots_txt.splitlines()
                      if p.lower().startswith(("disallow", "allow")) and ":" in p] if robots_txt else []
        sitemap_xml = await fetch_page(session, urljoin(base_url, "/sitemap.xml"))
        sitemap_eps = re.findall(r"<loc>(.*?)</loc>", sitemap_xml, re.I) if sitemap_xml else []
        openapi_eps = []
        for path in ["/swagger.json", "/openapi.json", "/api/swagger.json", "/api/openapi.json"]:
            swag = await fetch_page(session, urljoin(base_url, path))
            try:
                if swag and ("paths" in swag or "endpoints" in swag):
                    j = json.loads(swag)
                    for p in j.get("paths", []):
                        openapi_eps.append(urljoin(base_url, p))
            except Exception:
                continue
        sens_eps = await scan_sensitive_paths(session, base_url, args.http_method, headers)
        endpoints = list(unique([*all_eps, *robots_eps, *sitemap_eps, *openapi_eps, *sens_eps]))
    endpoints_objs = []
    for ep in endpoints:
        endpoints_objs.append({
            'url': ep,
            'status': None,
            'reason': '',
            'params': extract_context_parameters(ep),
            'sensitive': ep in sens_eps
        })
    endpoints_objs = await analyze_endpoints(
        endpoints_objs, args.max_concurrency, args.delay, args.http_method, headers, timeout
    )
    def should_write(ep):
        code = ep['status']
        if args.output_code and code not in args.output_code:
            return False
        if args.output_not_code and code in args.output_not_code:
            return False
        return True
    endpoints_write = [ep for ep in endpoints_objs if should_write(ep)]
    outfile = args.output or "hunter_out.txt"
    if outfile.endswith(".csv"):
        export_csv(endpoints_write, outfile)
    elif outfile.endswith(".pdf"):
        export_pdf(endpoints_write, outfile)
    else:
        export_txt(endpoints_write, outfile)
    print(f"\033[1;33m{len(endpoints_write)} endpoint(s) written to {outfile}\033[0m")
    print(f"\n\033[1;34m[+] Console output (AI analyzed, with parameters, colored):\033[0m\n")
    for ep in endpoints_objs:
        code = ep['status']
        if args.console_block_code and code in args.console_block_code:
            continue
        label = ""
        if ep['sensitive']: label = " [SENSITIVE]"
        if code == 200:
            col = "32"
        elif code == 404:
            col = "31"
        else:
            col = "37"
        print(f"\033[1;{col}m➤ {ep['url']} [{ep['status'] or '???'} {ep['reason']}], Params: {ep['params']}{label}\033[0m")
    print(f"\n\033[1;36mOnly endpoints matching selected status codes are written to output. Console is detailed!\033[0m")
    print(f"\033[1;35mFull scan took {time.time() - start_time:.2f} seconds.\033[0m")

def parse_args():
    parser = argparse.ArgumentParser(
        description="AI-powered API endpoint & sensitive path hunter for bug bounty/pentest. Colored output, flexible export!"
    )
    parser.add_argument("target", help="Target URL (ex: https://site.com)")
    parser.add_argument("--output", "-o", help="Output file (.txt, .csv, .pdf, default: hunter_out.txt)", default="hunter_out.txt")
    parser.add_argument("--output-code", "-oc", nargs="*", type=int, help="Only write these HTTP status codes to file (ex: -oc 200 403)")
    parser.add_argument("--output-not-code", "-onc", nargs="*", type=int, help="Don't write these HTTP status codes to file (ex: -onc 404)")
    parser.add_argument("--console-block-code", "-cbc", nargs="*", type=int, help="Don't show these HTTP codes in console (ex: -cbc 404)")
    parser.add_argument("--header", "-H", nargs="*", help="Extra HTTP header(s), ex: -H 'Authorization: Bearer X' 'X-Api-Key: abc'")
    parser.add_argument("--http-method", "-m", default="GET", help="HTTP method for endpoint check (default: GET)")
    parser.add_argument("--timeout", "-t", type=float, default=7, help="HTTP timeout (seconds, default: 7)")
    parser.add_argument("--delay", "-d", type=float, default=0, help="Delay between endpoint requests (seconds, default: 0)")
    parser.add_argument("--max-concurrency", "-T", type=int, default=10, help="Max concurrent endpoint checks (default: 10)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target
    asyncio.run(scan_all(args))

