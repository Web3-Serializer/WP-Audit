from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
from concurrent.futures import ThreadPoolExecutor

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "Directory Listing Scanner"
        self.description = "Check if directory listing is enabled on common WP directories."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)
        self.found_dirs = []

    def check_directory(self, path) -> bool:
        url = self.target_url.rstrip('/') + '/' + path.lstrip('/')
        try:
            response = self.session.get(url, allow_redirects=True)
            if response.status_code == 200 and "Index of" in response.text:
                self.logger.found(f"Directory listing enabled: {url}")
                self.found_dirs.append(path)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error checking {url}: {e}")
            return False

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        directories = [
            "wp-content/uploads/",
            "wp-content/plugins/",
            "wp-content/themes/",
            "wp-includes/",
            "wp-admin/"
        ]

        with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
            ex.map(self.check_directory, directories)

        self.wp_audit.gathered_informations.setdefault("directory_listing", []).extend(self.found_dirs)

        if not self.found_dirs:
            self.logger.warning("No directory listing enabled found.")
