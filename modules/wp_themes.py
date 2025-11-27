from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
import re

from concurrent.futures import ThreadPoolExecutor

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "WP Themes"
        self.description = "A module to gather WordPress themes on the target site."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)

        self.found_themes = []

    def find_by_homepage(self) -> bool:
        url = self.target_url + "/"
        try:
            response = self.session.get(url=url)
            if response.status_code == 200:
                matches = re.findall(r'wp-content/themes/(.*?)/.*?[css|js].*?ver=([0-9\.]*)', response.text, re.IGNORECASE)
                for match in matches:
                    theme_name = str(match[0]).replace("-master", "").replace(".min", "")
                    theme_version = match[1]
                    if theme_name in [theme["name"] for theme in self.found_themes]: continue
                    self.logger.found(f"Detected WordPress theme '{theme_name}' (version: {theme_version}) via homepage")
                    self.found_themes.append({"name": theme_name, "version": theme_version, "method": "homepage"})
                return self.found_themes if self.found_themes else False
            return False
        except Exception:
            self.logger.error(f"Error while checking homepage for themes")
            return False
        

    def check_theme(self, theme) -> bool:
        base = f"{self.target_url}/wp-content/themes/{theme}"
        paths = [
            ".zip",
            ".rar",
            ".tar.gz",
            "/style.css",
            "/style.min.css",
            "/css/style.css",
            "/css/style.min.css",
            "/assets/style.css",
            "/assets/css/style.css",
            "/assets/css/style.min.css",
        ]
        for p in paths:
            url = f"{base}{p}"
            try:
                resp = self.session.get(url)
                if resp.status_code != 200 or not resp.text:
                    continue

                header = resp.text[:8192]

                name_match = re.search(r"^\s*\*\s*Theme\s+Name:\s*(.+)$", header, re.IGNORECASE | re.MULTILINE)
                ver_match = re.search(r"^\s*\*\s*(?:Version|version|v)\s*[:\s]*([0-9A-Za-z\.\-]+)", header, re.IGNORECASE | re.MULTILINE)

                theme_name = name_match.group(1).strip() if name_match else theme
                theme_version = ver_match.group(1).strip() if ver_match else "unknown"

                self.logger.success(
                    f" - Found theme: {theme_name} (version: {theme_version}) via fuzzing path."
                )

                self.found_themes.append({
                    "name": theme_name,
                    "version": theme_version,
                    "method": "Path Fuzzing"
                })

            except Exception as e:
                self.logger.error(f"Error while checking theme {theme}/{p}: {e}")


    def run(self):
        if not self.enabled: return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        is_found_at_homepage = self.find_by_homepage()
        if is_found_at_homepage:
            self.wp_audit.gathered_informations.setdefault("wp_themes", []).extend(is_found_at_homepage)
        
        if self.wp_audit.aggressive:
            themes = open('./data/themes.fuzz').read().splitlines()
            self.logger.info(f"Loaded {len(themes)} themes for fuzzing")
            with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
                ex.map(self.check_theme, themes)

            self.wp_audit.gathered_informations.setdefault("wp_themes", []).extend(self.found_themes)

        if not self.found_themes:
            self.logger.warning("Could not find any WordPress themes")