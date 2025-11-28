from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger
import re
import json
import hashlib

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "WP Versions"
        self.description = "Detect WordPress versions using multiple methods."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)
        self.found_version = []

    def get_homepage(self):
        try:
            response = self.session.get(self.target_url + "/")
            if response.status_code == 200:
                return response.text
        except Exception as e:
            self.logger.error(f"Error fetching homepage: {e}")
        return ""

    def find_by_homepage(self, homepage_sc: str):
        match = re.search(r'name="generator" content="wordpress ([0-9\.]+)"', homepage_sc, re.IGNORECASE)
        if match:
            version = match.group(1)
            self.logger.found(f"Detected WordPress version {version} via meta generator")
            self.found_version.append({"version": version, "method": "Meta Generator"})
        
        versions = []
        matches_css = re.findall(r'<link[^>]+href=["\'][^"\']+ver=([0-9\.]+)["\']', homepage_sc, re.IGNORECASE)
        matches_js = re.findall(r'<script[^>]+src=["\'][^"\']+ver=([0-9\.]+)["\']', homepage_sc, re.IGNORECASE)
        versions += matches_css + matches_js
        if versions:
            most_common = max(set(versions), key=versions.count)
            self.logger.found(f"Detected WordPress version {most_common} via external resources")
            self.found_version.append({"version": most_common, "method": "External Resources"})

    def rss_feed(self):
        try:
            response = self.session.get(self.target_url + "/feed/")
            match = re.search(r'<generator>http://wordpress.org/\?v=([0-9\.]+)</generator>', response.text, re.IGNORECASE)
            if match:
                version = match.group(1)
                self.logger.success(f"Detected WordPress version {version} via RSS feed")
                self.found_version.append({"version": version, "method": "RSS Feed"})
        except:
            pass

    def readme_file(self):
        try:
            response = self.session.get(self.target_url + "/readme.html")
            match = re.search(r'<br\s*/>\s*Version ([0-9\.]+)', response.text, re.IGNORECASE)
            if match:
                version = match.group(1)
                self.logger.found(f"Detected WordPress version {version} via readme file")
                self.found_version.append({"version": version, "method": "Readme File"})
        except:
            pass

    def file_hash(self):
        try:
            with open('./data/wp-versions.json') as f:
                hash_data = json.load(f)
            for file, hash_map in hash_data.items():
                url = f"{self.target_url}/{file}"
                try:
                    resp = self.session.get(url)
                    if resp.status_code == 200:
                        md5 = hashlib.md5(resp.content).hexdigest()
                        if md5 in hash_map:
                            version = hash_map[md5]
                            self.logger.found(f"Detected WordPress version {version} via file hash ({file})")
                            self.found_version.append({"version": version, "method": "File Hash"})
                            return
                except Exception as e:
                    pass
        except Exception as e:
            pass

    def run(self):
        if not self.enabled: 
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        homepage_sc = self.get_homepage()
        if homepage_sc:
            self.find_by_homepage(homepage_sc)

        self.rss_feed()
        self.readme_file()

        if self.wp_audit.aggressive:
            self.file_hash() # generate 'a lot' of requests

        if self.found_version:
            self.wp_audit.gathered_informations.setdefault("wp_versions", []).extend(self.found_version)
        else:
            self.logger.warning("Could not detect WordPress version")