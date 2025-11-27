from colorama import Fore, Style, init

class Logger:
    def __init__(self, moduleName: str = "WP-Audit"):
        init(autoreset=True)
        self.loggerName = str(moduleName).replace(' ', "-")

    def info(self, message: str) -> None:
        print(f"    {Fore.CYAN}{Style.BRIGHT}[{self.loggerName}]{Style.RESET_ALL} {Fore.BLUE}(i){Style.RESET_ALL} {message}")

    def success(self, message: str) -> None:
        print(f"    {Fore.CYAN}{Style.BRIGHT}[{self.loggerName}]{Style.RESET_ALL} {Fore.GREEN}(+){Style.RESET_ALL} {message}")

    def warning(self, message: str) -> None:
        print(f"    {Fore.CYAN}{Style.BRIGHT}[{self.loggerName}]{Style.RESET_ALL} {Fore.YELLOW}(!){Style.RESET_ALL} {message}")

    def error(self, message: str) -> None:
        print(f"    {Fore.CYAN}{Style.BRIGHT}[{self.loggerName}]{Style.RESET_ALL} {Fore.RED}(x){Style.RESET_ALL} {message}")

    def found(self, message: str) -> None:
        print(f"    {Fore.CYAN}{Style.BRIGHT}[{self.loggerName}]{Style.RESET_ALL} {Fore.MAGENTA}(·) {Style.BRIGHT}{message}{Style.RESET_ALL}")