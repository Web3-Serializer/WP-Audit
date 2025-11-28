from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
import requests
from concurrent.futures import ThreadPoolExecutor

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "WP Vulnerabilities"
        self.description = "Check WordPress core, plugins, and themes for known vulnerabilities with full details."
        self.version = "1.3"
        self.author = "Serializer"
        self.enabled = True if self.wp_audit.check_vulns else False
        self.logger = Logger(moduleName=self.name)
        self.vulnerabilities = []

    def parse_version(self, version_str):
        if not version_str:
            return None
        version_str = str(version_str).lower().split('-')[0].split('+')[0]
        parts = []
        for part in version_str.split('.'):
            try:
                parts.append(int(part))
            except ValueError:
                pass
        return tuple(parts) if parts else None

    def compare_versions(self, installed_version, min_version=0, max_version=0):
        installed = self.parse_version(installed_version)
        if not installed:
            return False

        if min_version:
            min_v = self.parse_version(min_version)
            if min_v and installed < min_v:
                return False

        if max_version:
            max_v = self.parse_version(max_version)
            if max_v and installed > max_v:
                return False

        return True

    def fetch_vulns_wpvulnerability_api(self, type_: str, slug: str, installed_version: str = None):
        if not slug:
            return []

        api_url = f"https://www.wpvulnerability.net/{type_}/{slug}/"
        resp = self.session.get(api_url)
        if resp.status_code != 200:
            return []

        resp_json = resp.json()
        data = resp_json.get("data")

        if not data:
            return []

        vulns_list = data.get("vulnerability")
        if not vulns_list or not isinstance(vulns_list, list):
            return []

        collected = []
        for vuln_entry in vulns_list:
            sources = vuln_entry.get("source")

            for source in sources:
                if not source.get("name"):
                    continue

                operator = vuln_entry.get("operator", {})
                min_version = operator.get("min_version", 0)
                max_version = operator.get("max_version", 0)

                if installed_version and max_version:
                    if not self.compare_versions(installed_version, min_version, max_version):
                        # self.logger.warning(f"Skipping {source.get('id')}: installed v{installed_version} not in affected range v{min_version} to v{max_version}")
                        continue

                vuln = {
                    "type": type_,
                    "name": data.get("name"),
                    "slug": slug,
                    "installed_version": installed_version,
                    "affected_versions": {
                        "min": min_version,
                        "max": max_version
                    },
                    "vuln_name": source.get("name"),
                    "description": source.get("description"),
                    "cve": source.get("id"),
                    "date": source.get("date"),
                    "link": source.get("link"),
                    "cvss": {},
                    "cwe": []
                }
                try:
                    vuln["cvss"] = vuln_entry.get("impact", {}).get("cvss", {})
                    vuln["cwe"] = vuln_entry.get("impact", {}).get("cwe", [])
                except:
                    pass
                collected.append(vuln)

        return collected

    def check_core_vulns(self):
        wp_versions = self.wp_audit.gathered_informations.get("wp_versions", [])
        with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
            results = ex.map(self._check_core_vuln, wp_versions)
            for vulns in results:
                self.vulnerabilities.extend(vulns)

    def _check_core_vuln(self, version_info):
        version = version_info.get("version")
        if not version:
            return []
        vulns = self.fetch_vulns_wpvulnerability_api("core", version, version)
        for v in vulns:
            self.logger.found(f"Core vulnerability found: {v.get('vuln_name')} ({v.get('cve')}) affecting v{v.get('installed_version')}")
        return vulns

    def check_plugins_vulns(self):
        wp_plugins = self.wp_audit.gathered_informations.get("wp_plugins", [])
        with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
            results = ex.map(self._check_plugin_vuln, wp_plugins)
            for vulns in results:
                self.vulnerabilities.extend(vulns)

    def _check_plugin_vuln(self, plugin):
        name = plugin.get("name")
        version = plugin.get("version")
        if not name:
            return []
        vulns = self.fetch_vulns_wpvulnerability_api("plugin", name, version)
        for v in vulns:
            self.logger.found(f"Plugin vulnerability found: {v.get('vuln_name')} ({v.get('cve')}) affecting v{v.get('installed_version')}")
        return vulns

    def check_themes_vulns(self):
        wp_themes = self.wp_audit.gathered_informations.get("wp_themes", [])
        with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
            results = ex.map(self._check_theme_vuln, wp_themes)
            for vulns in results:
                self.vulnerabilities.extend(vulns)

    def _check_theme_vuln(self, theme):
        name = theme.get("name")
        version = theme.get("version")
        if not name:
            return []
        vulns = self.fetch_vulns_wpvulnerability_api("theme", name, version)
        for v in vulns:
            self.logger.found(f"Theme vulnerability found: {v.get('vuln_name')} ({v.get('cve')}) affecting v{v.get('installed_version')}")
        return vulns

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        self.check_core_vulns()
        self.check_plugins_vulns()
        self.check_themes_vulns()

        if self.vulnerabilities:
            self.logger.success(f"Found {len(self.vulnerabilities)} vulnerabilities")
            self.wp_audit.gathered_informations.setdefault("wp_vulnerabilities", []).extend(self.vulnerabilities)
        else:
            self.logger.info("No known vulnerabilities found for detected core, plugins, or themes")