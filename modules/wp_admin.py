from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)
        self.name = "WP Admin"
        self.description = "Check presence of WP admin, login, register and XML-RPC endpoints."
        self.version = "1.0"
        self.author = "Serializer"
        self.enabled = True
        self.logger = Logger(moduleName=self.name)

    def check_rest_exposure(self) -> bool:
        url = self.target_url + '/wp-json/'
        try:
            resp = self.session.get(url)
            if resp.status_code == 200:
                self.logger.success(f"REST API accessible: {url}")
                self.rest_endpoints.append(url)
                return True
            self.logger.info("Rest API not accessible")
            return False
        except Exception:
            return False

    def check_admin_ajax(self) -> bool:
        ajax_url = self.target_url + '/wp-admin/admin-ajax.php'

        try:
            response = self.session.get(ajax_url, allow_redirects=True)
            if response.status_code == 200:
                # sometimes WP return "0" for empty requests
                if response.text.strip() == "0" or "<!DOCTYPE html>" in response.text:
                    self.logger.success(f"Admin-Ajax endpoint accessible: {ajax_url}")
                    self.found = True
                    return True
            self.logger.info("Admin-Ajax endpoint not accessible")
            return False
        except Exception as e:
            self.logger.error(f"Error accessing Admin-Ajax endpoint: {e}")
            return False

    def check_registered_opened(self) -> bool:
        reg_url = self.target_url + '/wp-login.php?action=register'        
        try:
            response = self.session.get(reg_url)
            content = response.text if response.status_code == 200 else ""
        except Exception as e:
            return False

        if content:
            if '<form' in content:
                if ('Registration confirmation will be emailed to you' in content
                    or 'value="Register"' in content
                    or 'id="user_email"' in content):
                    self.logger.success(f"User registration is open: {reg_url}")
                    return True

        self.logger.info("User registration is closed")
        return False
    
    def check_xmlrpc(self) -> bool:
        xmlrpc_url = self.target_url + '/xmlrpc.php'

        xml_data = """
<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
        """

        headers = {"Content-Type": "text/xml"}

        try:
            response = self.session.post(xmlrpc_url, data=xml_data, headers=headers, allow_redirects=True)
            content = response.text
        except Exception as e:
            self.logger.error(f"Error accessing XML-RPC endpoint: {e}")
            return False

        if response.status_code == 200 and ('<methodResponse>' in content or 'XML-RPC server accepts POST requests only.' in content):
            self.logger.success(f"XML-RPC endpoint accessible: {xmlrpc_url}")
            return True

        self.logger.info("XML-RPC endpoint not accessible")
        return False
    
    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        self.wp_audit.gathered_informations['XmlRPC_enabled'] = self.check_xmlrpc()
        self.wp_audit.gathered_informations['Register_enabled'] = self.check_registered_opened()
        self.wp_audit.gathered_informations['AdminAjax_accessible'] = self.check_admin_ajax()
        self.wp_audit.gathered_informations['RestAPI_exposed'] = self.check_rest_exposure()

