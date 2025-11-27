from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
from concurrent.futures import ThreadPoolExecutor

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "Backup Files Scanner"
        self.description = "Scan for exposed backup files in the webroot or WP directories."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)
        self.found_backups = []

    def check_backup_file(self, path) -> bool:
        url = self.target_url.rstrip('/') + '/' + path.lstrip('/')
        try:
            response = self.session.get(url, allow_redirects=True)
            if response.status_code == 200 and response.text.strip():
                self.logger.found(f"Exposed backup file found: {url}")
                self.found_backups.append(path)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error checking {url}: {e}")
            return False

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        backup_files = [
            "wp-config.php.bak",
            "wp-config.php",
            "wp-config.php.save",
            "wp-config.php.old",
            "backup.zip",
            "backup.tar.gz",
            "backup.sql",
            "database.sql",
            "site-backup.tar",
            "site-backup.zip",
            "wp-content/uploads/backup.zip",
        ]

        with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
            ex.map(self.check_backup_file, backup_files)

        self.wp_audit.gathered_informations.setdefault("exposed_backup_files", []).extend(self.found_backups)

        if not self.found_backups:
            self.logger.warning("No exposed backup files found.")
