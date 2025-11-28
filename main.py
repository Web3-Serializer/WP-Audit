import os, sys, tls_client, time, fake_useragent
from libs.logger import Logger
from libs.LLM import LLMReportGenerator
from glob import glob
import argparse, json, datetime
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv

class WP_Audit:

    def __init__(self, target_url, user_agent: str = None, browser_identifier: str = "chrome_108", 
                 proxies: dict = None, modules_to_load: str = None, threads: int = 5,
                 aggressive: bool = False, bruteforce: str = None,
                 check_vulns: bool = False):
        
        self.modules_to_load = [m.strip() for m in modules_to_load.split(",")] if modules_to_load else None
        self.session = tls_client.Session(
            client_identifier=browser_identifier,
            random_tls_extension_order=True
        )
        self.logger = Logger()

        if proxies:
            self.session.proxies.update(proxies)
        self.session.headers.update({
            "User-Agent": user_agent if user_agent else fake_useragent.UserAgent().random,
        })

        self.target_url = target_url.rstrip("/")
        self.modules = []

        self.threads = threads
        self.aggressive = aggressive
        self.bruteforce = bruteforce
        self.check_vulns = check_vulns

        self.load_modules()

        self.gathered_informations = {
            "wp_users": [],
            "wp_plugins": [],
            "wp_themes": [],
            "wp_versions": []
        }

        self.logger.info(f"Initialized WP_Audit, target: {self.target_url}, modules loaded: {len(self.modules)}, mode: {'Aggressive' if self.aggressive else 'Normal'}")

    def detect_wp(self) -> bool:
        endPointsHints = [
            "site",
            "readme.html",
            "robots.txt",
            "feed",
            "rss",
            "xmlrpc.php",
            "wp-json",
            "wp-admin",
            "wp-login",
        ]
        textHints = [
            "wp-content",
            "wp-includes",
            "WordPress",
            "wordpress.org",
            "wp-emoji-release.min.js",
        ]
        for endpoint in endPointsHints:
            url = self.target_url + "/" + str(endpoint)
            try:
                response = self.session.get(url=url)
                if response.status_code == 200 or response.status_code == 301:
                    for hint in textHints:
                        if hint in str(response.text).lower():
                            self.logger.success(f"Detected WordPress via {url}")
                            return True
            except Exception as e:
                self.logger.warning(f"Error accessing {url}: {e}")

    def import_module(self, module_name: str):
        try:
            module_path = f"modules.{module_name}"
            module = __import__(module_path, fromlist=[''])
            module_class = getattr(module, "Module")
            instance = module_class(self)
            return instance
        except (ImportError, AttributeError) as e:
            self.logger.error(f"Failed to import module {module_name}: {e}")
            return None

    def load_modules(self):
        module_files = glob(os.path.join(os.path.dirname(__file__), 'modules', '*.py'))
        for module_file in module_files:
            
            module_name = os.path.basename(module_file)[:-3]
            if module_name == "__init__":
                continue
            if self.modules_to_load and module_name not in self.modules_to_load:
                continue
            module = self.import_module(module_name)
            if module:
                self.modules.append(module)

    def start_scan(self):
        if not self.detect_wp():
            self.logger.error("The target site does not appear to be a WordPress site. Exiting.")
            sys.exit(1)

        self.modules.sort(key=lambda m: getattr(m, "priority", 10))

        self.logger.info(
            f"Starting scan on {self.target_url} "
            f"with {len(self.modules)} modules."
        )

        for module in self.modules:
            self.logger.info(
                f"Executing module: {module.getName()} [priority={module.priority}]"
            )
            try:
                module.run()
                self.logger.success(
                    f"Module {module.getName()} completed successfully."
                )
            except Exception as e:
                self.logger.error(
                    f"Module {module.getName()} failed: {e}"
            )



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WP Audit Tool - AI Powered & Modulable WordPress Security Scanner")

    parser.add_argument("target_url", help="The target WordPress site URL")
    parser.add_argument("--user-agent", help="Custom User-Agent string", default=None)
    parser.add_argument("--browser", help="Browser identifier for TLS client", default="chrome_108")
    
    parser.add_argument("--modules", help="Comma-separated list of modules to load", default=None)
    parser.add_argument("--list-modules", help="List all available modules", action="store_true")
    parser.add_argument('--threads', type=int, help='Number of threads to use in modules', default=5)

    parser.add_argument('--aggressive', help='Enable aggressive scanning mode (fuzzing, spamming, etc)', action='store_true')
    
    parser.add_argument(
        '--brute',
        help='Select brute-force target: "admin" brute-forces the default admin user; '
        '"enum" brute-forces all users enumerated by the wp_user module.',
        type=str,
        choices=['admin', 'enum']
    )

    parser.add_argument('--check-vulns', help='Enable WP Vulns module, check for core, plugins, and themes for known vulnerabilities.', action='store_true')

    parser.add_argument(
        '--report', 
        choices=['html', 'markdown'], 
        help=(
            "Generate a complete audit report of the scan.\n"
            "Options:\n"
            "  html   - Structured HTML report (browser friendly)\n"
            "  markdown - Enhanced markdown syntax report with explanations, summaries, and descriptions generated using a LLM model."
        )
    )

    parser.add_argument("--proxy", help="Proxy server (format: http://user:pass@host:port)", default=None)
    args = parser.parse_args()

    load_dotenv()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    target_url = args.target_url
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + str(target_url)

    wp_audit = WP_Audit(
        target_url=target_url, 
        user_agent=args.user_agent, 
        browser_identifier=args.browser,
        proxies=proxies,
        modules_to_load=args.modules, 
        threads=args.threads, 
        aggressive=args.aggressive,
        bruteforce=args.brute,
        check_vulns=args.check_vulns
    )
    
    if args.list_modules:
        wp_audit.logger.info(f"Available Modules ({len(wp_audit.modules)}):")
        for module in wp_audit.modules:
            wp_audit.logger.found(f"    {module.getName()}: {module.getDescription()} (v{module.getVersion()}) by {module.getAuthor()}")
        sys.exit(0)
    
    wp_audit.start_scan()

    if args.report != None:


        scan_data = wp_audit.gathered_informations or {}
        scan_json = json.dumps(scan_data, indent=2)
        report_type = str(args.report).lower()
        report_filename = None
        scanned_domain = urlparse(wp_audit.target_url).netloc

        scan_date = datetime.datetime.now().strftime("%Y-%m-%d")
        report_id = str(int(time.time()))
        report_content = ""

        output_path = "./reports"
        templates_path = "./templates"

        if report_type == "html":

            template_path = Path(f'{templates_path}/default.html')
            if not template_path.exists():
                wp_audit.logger.error(f"Template not found: {template_path}")

            template_content = template_path.read_text(encoding='utf-8')

            report_content = template_content.replace("%DOMAIN%", scanned_domain)
            report_content = report_content.replace("%SCAN_DATA%", scan_json)
            report_content = report_content.replace("%DATE%", scan_date)
            report_content = report_content.replace("%REPORT_ID%", report_id)

            report_filename = f"{output_path}/report_{scanned_domain}.html"

        elif report_type == "markdown":
            generator = LLMReportGenerator(
                model=os.getenv('OLLAMA_MODEL')
            )

            system_prompt = Path(f'{templates_path}/default.md').read_text(encoding='utf-8')

            report_content = generator.generate_markdown_report(
                scan_data=scan_json,
                domain=scanned_domain,
                scan_date=scan_date,
                report_id=report_id,
                system_prompt=system_prompt

            )
            report_filename = f"{output_path}/report_{scanned_domain}.md"
        
        Path(report_filename).write_text(report_content, encoding="utf-8")
        if report_filename: wp_audit.logger.success(f"Report generated: {report_filename}")