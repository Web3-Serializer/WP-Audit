from main import WP_Audit

class ModuleBase:
    def __init__(self, wp_audit_instance: WP_Audit):
        self.wp_audit = wp_audit_instance

        self.session = wp_audit_instance.session
        self.target_url = wp_audit_instance.target_url

        self.name = "Base Module"
        self.description = "This is a base module."
        self.version = "1.0"
        self.author = "Author Name"
        self.priority = 2 # default priority
        self.logger = None

    def getName(self) -> str:
        return self.name
    
    def getDescription(self) -> str:
        return self.description
    
    def getVersion(self) -> str:
        return self.version
    
    def getAuthor(self) -> str:
        return self.author
    
    def run(self) -> None:
        raise NotImplementedError("Subclasses should implement this method.")