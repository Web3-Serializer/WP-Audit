from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
from urllib.parse import urljoin, urlparse
import time

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)

        self.name = "Open Redirect Checker"
        self.description = "Detects potential open redirect vulnerabilities in WordPress login and other endpoints."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True

        self.logger = Logger(moduleName=self.name)

        self.results = []

        self.test_paths = [
            # Core WordPress endpoints
            "/wp-login.php?redirect_to=https://example.com",
            "/wp-login.php?redirect_to=http://example.com",
            "/wp-login.php?redirect_to=//example.com",
            "/wp-login.php?redirect_to=/\\example.com",
            "/wp-login.php?redirect_to=%2F%2Fexample.com",
            "/wp-login.php?redirect_to=%5C%5Cexample.com",
            "/wp-login.php?redirect_to=//evil.com/%2e%2e",
            "/wp-login.php?redirect_to=/wp-admin/",

            # Logout endpoint often leaks redirect
            "/wp-login.php?action=logout&redirect_to=https://example.com",
            "/wp-login.php?action=logout&redirect_to=//example.com",
            "/wp-login.php?action=logout&redirect_to=%2F%2Fevil.com",

            # Lost password page
            "/wp-login.php?action=lostpassword&redirect_to=https://example.com",

            # Register page
            "/wp-login.php?action=register&redirect_to=https://example.com",

            # wp-admin redirect behavior
            "/wp-admin/?redirect_to=https://example.com",
            "/wp-admin/profile.php?redirect_to=https://example.com",

            # Common plugin endpoints known for redirect issues
            "/?redirect_to=https://example.com",
            "/?r=https://example.com",
            "/?go=https://example.com",
            "/?url=https://example.com",
            "/?target=https://example.com",
            "/?next=https://example.com",
            "/?dest=https://example.com",
            "/?destination=https://example.com",
            "/?forward=https://example.com",

            # WooCommerce (has multiple redirect params)
            "/my-account/?redirect_to=https://example.com",
            "/my-account/lost-password/?redirect_to=https://example.com",
            "/checkout/?redirect_to=https://example.com",

            # bbPress login redirect
            "/forums/?redirect_to=https://example.com",

            # Elementor login widget
            "/?login_error&redirect_to=https://example.com",

            # Wordfence login redirect handler
            "/?wfaction=login&redirect_to=https://example.com",

            # Jetpack / JSON login endpoints
            "/xmlrpc.php?redirect_to=https://example.com",

            # JSON API plugin endpoints
            "/wp-json/wp/v2/users?redirect_to=https://example.com",
            "/wp-json/?redirect_to=https://example.com",

            # Yoast SEO redirect param often exists in preview pages
            "/?yoast_redirect_to=https://example.com",

            # Polylang / WPML language switchers
            "/?lang=fr&redirect_to=https://example.com",
            "/?lang=en&redirect_to=//example.com",

            # Common obfuscated redirect attempts
            "/wp-login.php?redirect_to=%252F%252Fevil.com",
            "/wp-login.php?redirect_to=%5Cexample.com",
            "/wp-login.php?redirect_to=%2F..%2Fexample.com",
        ]

    def _check_redirect(self, path: str):
        url = urljoin(self.target_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = self.session.get(url, allow_redirects=False)
            status = response.status_code
            location = response.headers.get("Location", "")

            if status in [301, 302, 303, 307, 308] and location:
                parsed = urlparse(location)
                if parsed.netloc and parsed.netloc != urlparse(self.target_url).netloc:
                    finding = {
                        "tested_url": url,
                        "status_code": status,
                        "redirect_to": location
                    }
                    self.results.append(finding)
                    self.logger.warning(f"Potential open redirect detected: {url} -> {location}")
        except Exception as e:
            self.logger.error(f"Error testing {url}: {e}")

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        for path in self.test_paths:
            self._check_redirect(path)

        if self.results:
            self.wp_audit.gathered_informations.setdefault("open_redirects", [])
            self.wp_audit.gathered_informations["open_redirects"].extend(self.results)
            self.logger.success(f"{len(self.results)} potential open redirect(s) detected.")
        else:
            self.logger.warning("No open redirects detected.")