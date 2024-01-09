import logging
import colorlog

# Define the custom logging level for success
SUCCESS = 35
logging.SUCCESS = SUCCESS
logging.addLevelName(SUCCESS, "SUCCESS")

class CustomLogger(logging.Logger):
    def success(self, msg, *args, **kwargs):
        if self.isEnabledFor(SUCCESS):
            self._log(SUCCESS, msg, args, **kwargs)

log = CustomLogger(__name__)
log.setLevel(logging.INFO)  # Set the default level

# Define log formats with color and include only time in timestamp
formatter = colorlog.ColoredFormatter(
    '%(log_color)s[%(asctime)s] - [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
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

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
log.addHandler(console_handler)

# File Handler
file_handler = logging.FileHandler('NMB_output.log') 
file_handler.setFormatter(formatter)
log.addHandler(file_handler)
