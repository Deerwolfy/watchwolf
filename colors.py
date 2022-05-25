class colors:
    OK = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'

    def disable(self):
        self.OK = ''
        self.WARNING = ''
        self.ERROR = ''
        self.END = ''
