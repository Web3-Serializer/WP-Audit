from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)

        self.name = "WordPress Headers Scanner"
        self.description = "Collects and analyzes HTTP response headers for WordPress security indicators."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True

        self.logger = Logger(moduleName=self.name)

    def to_str(self, value):
        if isinstance(value, (list, tuple)):
            return ", ".join(map(str, value))
        return str(value) if value is not None else ""

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        try:
            response = self.session.get(self.target_url, allow_redirects=True)
        except Exception as e:
            self.logger.error(f"Failed to fetch headers: {e}")
            return

        headers = {k.lower(): self.to_str(v) for k, v in response.headers.items()}

        wp_indicators = {
            "x-pingback": headers.get("x-pingback"),
            "link": headers.get("link") if "wp-json" in headers.get("link", "").lower() else None,
            "x-powered-by": headers.get("x-powered-by"),
            "server": headers.get("server"),
            "content-type": headers.get("content-type")
        }

        security_headers = {
            "strict-transport-security": headers.get("strict-transport-security"),
            "x-content-type-options": headers.get("x-content-type-options"),
            "x-frame-options": headers.get("x-frame-options"),
            "x-xss-protection": headers.get("x-xss-protection"),
            "referrer-policy": headers.get("referrer-policy"),
            "content-security-policy": headers.get("content-security-policy")
        }


        self.wp_audit.gathered_informations.setdefault("headers", {})
        self.wp_audit.gathered_informations["headers"]["raw"] = headers
        self.wp_audit.gathered_informations["headers"]["wp_indicators"] = wp_indicators
        self.wp_audit.gathered_informations["headers"]["security_headers"] = security_headers

        missing = [h for h, v in security_headers.items() if v is None]
        if missing:
            self.logger.warning(f"Missing important security headers: {', '.join(missing)}")
        else:
            self.logger.success("All major security headers appear to be present.")