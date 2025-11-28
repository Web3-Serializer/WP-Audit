from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)

        self.name = "WAF / Firewall Detection"
        self.description = "Detects common WAFs and firewalls via headers, paths, and behavioral patterns."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True

        self.logger = Logger(moduleName=self.name)

        self.fingerprints = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id", "server: cloudflare"],
            "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
            "Wordfence": ["x-wf-blocked", "x-wf-application", "x-wf-ls"],
            "ModSecurity": ["mod_security", "modsecurity", "x-mod-security", "server: mod_security","x-modsec","x-modsec-hit"],
            "Imunify360": ["imunify360", "x-imunify360", "server: imunify360"],
            "Akamai": ["akamai", "x-akamai-transformed", "akamai-ghost", "server: akamai"],
            "AWS WAF": ["x-amzn-waf-id", "x-amzn-waf-status", "awswaf"],
            "Azure Front Door": ["azurefdid", "x-azure-ref", "server: azure"],
            "Fastly": ["fastly", "fastly-cache", "x-served-by: cache-", "via: 1.1 varnish"],
            "OVHCloud Firewall": ["ovh", "x-ovh-queryid", "ovhcdn", "server: ovh", "x-cdn-request-id"],
            "Cisco IronPort": ["ironport", "cisco", "x-ironport"],
            "Barracuda WAF": ["barracuda", "x-barracuda", "server: barracuda"],
            "FortiWeb (Fortinet)": ["fortiweb", "fortiguard", "server: fortinet"],
            "F5 BIG-IP ASM": ["bigip", "f5", "x-waf-status", "x-asm", "x-bigip"],
            "Imperva Incapsula": ["incapsula", "x-iinfo", "x-cdn", "visid_incap"],
            "LiteSpeed WAF": ["litespeed", "x-litespeed-tag", "server: litespeed"],
            "Nginx WAF (Generic)": ["nginx-waf", "modsecurity-nginx", "server: nginx"],
            "OpenResty / WAF": ["openresty", "server: openresty"],
            "SiteGround SG WAF": ["sg-optimizer", "server: siteground"],
            "IONOS / 1&1": ["1and1", "ionos", "server: 1and1"],
            "Path-Based Firewall Indicators": [
                "/cdn-cgi/", "/sucuri-firewall", "/wp-content/mu-plugins/sucuri",
                "/wp-content/mu-plugins/wordfence-waf.php",
                "/wp-content/plugins/better-wp-security",
                "/wp-content/mu-plugins/sg-cachepress"
            ]
        }

        self.results = {
            "detected": [],
            "raw_headers": {},
            "behavior": {}
        }

    def _normalize_header_value(self, value):
        if isinstance(value, (list, tuple)):
            return ", ".join(map(str, value)).lower()
        if value is None:
            return ""
        return str(value).lower()

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        try:
            response = self.session.get(self.target_url, allow_redirects=True)
            headers = {k.lower(): self._normalize_header_value(v) for k, v in response.headers.items()}
            self.results["raw_headers"] = headers

            for waf, checks in self.fingerprints.items():
                for c in checks:
                    if c.lower() in str(headers):
                        if waf not in self.results["detected"]:
                            self.results["detected"].append(waf)
                            self.logger.warning(f"Detected WAF: {waf}")

            test_payload = "<script>alert(1)</script>"
            behavior_response = self.session.get(self.target_url + "/?test=" + test_payload, allow_redirects=True)
            behavior_code = behavior_response.status_code

            self.results["behavior"] = {
                "payload_status": behavior_code,
                "blocked": True if behavior_code in [403, 406, 501] else False
            }

            if self.results["behavior"]["blocked"]:
                self.logger.warning("The server appears to block malicious payloads (behavioral WAF detected).")

            self.wp_audit.gathered_informations.setdefault("waf_detection", {})
            self.wp_audit.gathered_informations["waf_detection"] = self.results

            if not self.results["detected"] and not self.results["behavior"]["blocked"]:
                self.logger.warning("No WAF detected.")

        except Exception as e:
            self.logger.error(f"Error detecting WAF: {e}")
