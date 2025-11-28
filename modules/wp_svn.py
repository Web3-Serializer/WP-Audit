from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
from concurrent.futures import ThreadPoolExecutor

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "Exposed SVN Scanner"
        self.description = "Check if SVN configuration files are publicly accessible."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)

        self.found_svn_files = []

    def check_svn_file(self, path) -> bool:
        url = self.target_url.rstrip('/') + '/' + path.lstrip('/')
        try:
            response = self.session.get(url, allow_redirects=True)
            if response.status_code == 200 and response.text.strip():
                self.logger.found(f"Exposed SVN file found: {url}")
                self.found_svn_files.append(path)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error checking {url}: {e}")
            return False

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        payloads = [
            ".svn/entries",
            ".svn/wc.db",
            ".svn/text-base/",
            ".svn/all-wcprops",
            ".svn/format",
            ".svn/prop-base/"
        ]

        with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
            ex.map(self.check_svn_file, payloads)

        self.wp_audit.gathered_informations.setdefault("svn_files", []).extend(self.found_svn_files)

        if not self.found_svn_files:
            self.logger.warning("No exposed SVN files found.")