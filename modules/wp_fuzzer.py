from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger

from concurrent.futures import ThreadPoolExecutor

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.priority = 5
        self.name = "WP Fuzzer"
        self.description = "A module to perform fuzzing on WordPress sites."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True if self.wp_audit.aggressive else False # Enable only in aggressive mode (lots of requests)
        self.logger = Logger(moduleName=self.name)

        self.found_endpoints = []

    def check_endpoint(self, endpoint: str) -> bool:
        url = self.target_url + "/" + endpoint
        try:
            response = self.session.get(url=url)
            if response.status_code == 200:
                self.logger.found(f"Found valid endpoint: {url}")
                self.found_endpoints.append(url)
        except Exception:
            pass

    def run(self):
        if not self.enabled: return

        self.logger.info(f"Running {self.name} on {self.target_url}")
        endpoints = open('./data/urls.fuzz').read().splitlines()

        with ThreadPoolExecutor(max_workers=3) as ex:
            ex.map(self.check_endpoint, endpoints)

        self.wp_audit.gathered_informations.setdefault("wp_fuzzer", []).extend(self.found_endpoints)
    
        if not self.found_endpoints:
            self.logger.warning("Could not find any valid endpoints via fuzzing")