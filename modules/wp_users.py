from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.priority = 1
        self.name = "WP Users"
        self.description = "A module to gather WordPress users on the target site."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)

        self.found_users = []

    def gather_wp_users(self) -> None:
        url = self.target_url + "/wp-json/wp/v2/users"
        try:
            response = self.session.get(url=url)
            if response.status_code == 200:
                users = response.json()
                for user in users:
                    self.found_users.append({"id": user.get("id"), "slug": user.get("slug"), "name": user.get("name"), "method": "wp-json"})
                    self.logger.found(f"Found user: {user.get('name')} (Username: {user.get('slug')}, ID: {user.get('id')}) via wp-json endpoint")
        except Exception as e:
            pass

    def gather_wpcom_authors(self) -> None:
        site = self.target_url.replace("http://", "").replace("https://", "").strip("/")
        url = f"https://public-api.wordpress.com/rest/v1.1/sites/{site}/posts"
        params = {
            "number": 100,
            "pretty": True,
            "fields": "author"
        }

        try:
            response = self.session.get(url=url, params=params)
            if response.status_code == 200:
                data = response.json()
                posts = data.get("posts", [])
                for post in posts:
                    author = post.get("author")
                    if author and author.get("ID") not in [u["id"] for u in self.found_users]:
                        self.found_users.append({
                            "id": author.get("ID"),
                            "slug": author.get("slug"),
                            "name": author.get("name"),
                            "method": "wpcom_posts"
                        })
                        self.logger.success(
                            f" - Found user: {author.get('name')} (Username: {author.get('slug')}, ID: {author.get('ID')}) via WP.com posts"
                        )
        except Exception as e:
            pass


    def gather_public_users(self) -> None:
        endpoints = [
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts",
            "/wp-json/wp/v2/pages",
            "/wp-json/wp/v2/media",
            "/wp-json/wp/v2/comments"
        ]
        for endpoint in endpoints:
            url = self.target_url + endpoint
            try:
                response = self.session.get(url=url)
                if response.status_code == 200:
                    data = response.json()
                    for item in data:

                        href = item.get("link", "")
                        if "/author/" not in href: continue

                        author_id = item.get("id")
                        author_slug = item.get("slug")
                        author_name = item.get("name")

                        if not author_id: continue
                        if author_id in [u["id"] for u in self.found_users]: continue
                       
                        self.logger.found(f"Found user: {author_name} (Username: {author_slug}, ID: {author_id}) via public endpoint {endpoint}")
                        self.found_users.append({"id": author_id, "slug": author_slug, "name": author_name, "method": "public-endpoint"})
            except Exception as e:
                pass

    def run(self):
        if not self.enabled: return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        self.gather_wp_users()
        self.gather_public_users()
        self.gather_wpcom_authors()

        self.wp_audit.gathered_informations.setdefault("wp_users", []).extend(self.found_users)