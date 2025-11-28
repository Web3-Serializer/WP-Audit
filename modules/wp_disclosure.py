from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
import re
import time

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)

        self.name = "Internal Path Disclosure Scanner"
        self.description = "Searches for internal path disclosures and error stack traces in responses."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True

        self.logger = Logger(moduleName=self.name)

        self.payloads = [
            "/",  # homepage (often reveals errors)
            "/non-existent-404-unique-token",  # force 404 pages (may leak paths)
            "/wp-login.php",
            "/wp-admin/",
            "/wp-admin/admin-ajax.php",
            "/xmlrpc.php",
            "/?p=999999999",  # high id to produce an error in some sites
            "/?author=9999999",
            "/wp-content/debug.log",
            "/wp-content/uploads/../../wp-config.php",  # sometimes misconfigured servers echo paths
            "/wp-content/plugins/",
            "/wp-content/themes/",
            "/index.php?option=com_content",  # common CMS patterns
            "/.env",
            "/phpinfo.php",
        ]

        self.patterns = {
            "php_fatal": re.compile(r"(Fatal error:.*in\s+([/\w\-\._~]+))", re.IGNORECASE),
            "php_warning": re.compile(r"(Warning:.*in\s+([/\w\-\._~]+))", re.IGNORECASE),
            "php_notice": re.compile(r"(Notice:.*in\s+([/\w\-\._~]+))", re.IGNORECASE),
            "python_trace": re.compile(r"Traceback \(most recent call last\):"),
            "java_stack": re.compile(r"Exception in thread \"[\w\-]+\"|at [\w\.$_]+\(.*:\d+\)"),
            "file_reference": re.compile(r"(File \"([^\"]+)\", line \d+)", re.IGNORECASE),
            "env_file": re.compile(r"\.env"),
        }

        self.request_delay = 0.15

    def _normalize_value(self, value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple)):
            return ", ".join(map(str, value))
        return str(value)

    def _analyze_text(self, url, text):
        findings = []

        snippet = text[:20000] if isinstance(text, str) else ""

        for key, regex in self.patterns.items():
            for match in regex.finditer(snippet):
                full = match.group(0)
                groups = match.groups()
                candidate = None
                if len(groups) >= 2 and groups[1]:
                    candidate = groups[1]
                else:
                    candidate = full

                findings.append({
                    "type": key,
                    "match": full.strip(),
                    "path_candidate": candidate.strip() if candidate else full.strip(),
                    "url": url
                })

        unique = []
        seen = set()
        for f in findings:
            key = (f["type"], f["path_candidate"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _check_url(self, path):
        target = self.target_url.rstrip("/")
        url = urljoin(target + "/", path.lstrip("/"))
        try:
            resp = self.session.get(url, allow_redirects=True)

            headers = {k.lower(): self._normalize_value(v) for k, v in resp.headers.items()}
            text = resp.text if resp.text else ""
            findings = self._analyze_text(url, text)

            header_findings = []
            for hk, hv in headers.items():
                for key, regex in self.patterns.items():
                    m = regex.search(hv)
                    if m:
                        header_findings.append({
                            "type": f"header_{key}",
                            "match": m.group(0),
                            "path_candidate": (m.groups()[1] if len(m.groups()) >= 2 and m.groups()[1] else m.group(0)),
                            "url": url,
                            "header": hk,
                            "header_value": hv
                        })

            all_findings = findings + header_findings

            return {
                "url": url,
                "status_code": resp.status_code,
                "content_length": len(text),
                "findings": all_findings
            }

        except Exception as e:
            self.logger.error(f"Request error for {url}: {e}")
            return {
                "url": url,
                "status_code": None,
                "content_length": 0,
                "findings": [],
                "error": str(e)
            }

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        all_results = []

        payloads = list(self.payloads)

        with ThreadPoolExecutor(max_workers=getattr(self.wp_audit, "threads", 5)) as pool:
            futures = {pool.submit(self._check_url, p): p for p in payloads}
            for future in as_completed(futures):
                res = future.result()

                time.sleep(self.request_delay)
                if res:
                    if res.get("findings"):
                        self.logger.found(f"{len(res['findings'])} potential disclosure(s) on {res['url']} (HTTP {res.get('status_code')})")
                        all_results.append(res)

        if all_results:
            self.wp_audit.gathered_informations.setdefault("internal_path_disclosures", [])
            self.wp_audit.gathered_informations["internal_path_disclosures"].extend(all_results)
            self.logger.success(f"Internal path disclosure scanner found {sum(len(r['findings']) for r in all_results)} findings across {len(all_results)} URLs.")
        else:
            self.logger.warning("No internal path disclosures detected.")