from colors import colors

class Logger():
    color = colors()

    @staticmethod
    def err(msg):
        print("ERROR: " + Logger.color.ERROR + msg + Logger.color.END)

    @staticmethod
    def warn(msg):
        print("WARNING: " + Logger.color.WARNING + msg + Logger.color.END)

    @staticmethod
    def info(msg):
        print("INFO: " + msg)

Logger.color.disable()
