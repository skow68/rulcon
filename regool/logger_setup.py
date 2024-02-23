import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
file_handler = logging.FileHandler('run.log')
console_handler.setLevel(logging.ERROR)
file_handler.setLevel(logging.DEBUG)
console_format = logging.Formatter('%(levelname)s - %(message)s')
file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_format)
file_handler.setFormatter(file_format)
logger.addHandler(console_handler)
logger.addHandler(file_handler)