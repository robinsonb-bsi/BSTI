import logging
import colorlog
class CustomLogger(logging.Logger):
    def __init__(self, name):
        super().__init__(name)
        self.SUCCESS = 35
        logging.addLevelName(self.SUCCESS, "SUCCESS")
        self.setLevel(logging.INFO)
        formatter = colorlog.ColoredFormatter(
            '%(log_color)s[%(levelname)s] %(message)s',
            datefmt=None,
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'WARNING': 'yellow',
                'INFO': 'blue',
                'ERROR': 'red',
                'CRITICAL': 'bold_red',
                'SUCCESS': 'green'
            },
            secondary_log_colors={},
            style='%'
        )
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.addHandler(console_handler)

    def success(self, msg, *args, **kwargs):
        if self.isEnabledFor(self.SUCCESS):
            self._log(self.SUCCESS, msg, args, **kwargs)

log = CustomLogger(__name__)