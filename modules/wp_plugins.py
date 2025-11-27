from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
from concurrent.futures import ThreadPoolExecutor
import re

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "WP Plugins"
        self.description = "A module to gather WordPress plugins on the target site."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)
    
        self.found_plugins = []

    def find_by_homepage(self) -> list:
        url = self.target_url + "/"
        try:
            response = self.session.get(url=url)
            if response.status_code == 200:
                matches = re.findall(r'wp-content/plugins/(.*?)/.*?[css|js].*?ver=([0-9\.]*)', response.text, re.IGNORECASE)
                for match in matches:
                    plugin_name = str(match[0]).replace("-master", "").replace(".min", "")
                    plugin_version = match[1]
                    if plugin_name in [plugin["name"] for plugin in self.found_plugins]: continue
                    self.found_plugins.append({"name": plugin_name, "version": plugin_version, "method": "homepage"})
                    self.logger.found(f"Detected WordPress plugin '{plugin_name}' (version: {plugin_version}) via homepage")
            return self.found_plugins if self.found_plugins else False
        except Exception:
            self.logger.error(f"Error while checking homepage for plugins")
            return False

    def check_plugin(self, plugin) -> bool:
        common_plugins_paths = [
            "includes/css/styles.css",
            "assets/css/styles.css",
            "css/styles.css",
            "style.css",
            "readme.txt",
            "readme.html",
            "readme.md",
            "js/scripts.js",
            "assets/js/scripts.js",
            "includes/js/scripts.js",
        ]
        found = False
        for path in common_plugins_paths:
            url = f"{self.target_url}/wp-content/plugins/{plugin}/{path}"
            self.logger.info(f"Checking plugin endpoint: {url}")
            try:
                response = self.session.get(url=url)
                if response.status_code == 200:
                    match = re.search(r'ver(?:sion)?[=:\"\']*\s*([0-9\.]+)', response.text, re.IGNORECASE)
                    version = match.group(1) if match else "unknown"
                    if not any(p["name"] == plugin for p in self.found_plugins):
                        self.found_plugins.append({"name": plugin, "version": version, "method": "fuzzing"})
                    self.logger.found(f"Found plugin: {plugin} (version: {version}) via {path}")
                    found = True
            except Exception as e:
                self.logger.error(f"Error while checking plugin endpoint {plugin}/{path}: {e}")
        return found


    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        found_at_homepage = self.find_by_homepage()
        if found_at_homepage:
            self.wp_audit.gathered_informations.setdefault("wp_plugins", []).extend(found_at_homepage)

        if self.wp_audit.aggressive:
            plugins = open('./data/plugins.fuzz').read().splitlines()
            self.logger.info(f"Loaded {len(plugins)} plugins for fuzzing")
            with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
                ex.map(self.check_plugin, plugins)

            self.wp_audit.gathered_informations.setdefault("wp_plugins", []).extend(self.found_plugins)

        if not self.found_plugins:
            self.logger.warning("Could not find any WordPress plugins")