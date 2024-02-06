import logging

logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
file_handler = logging.FileHandler('run.log')
console_handler.setLevel(logging.error)
file_handler.setLevel(logging.debug)
console_format = logging.Formatter('%(levelname)s - %(message)s')
file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(c_format)
file_handler.setFormatter(f_format)
logger.addHandler(console_handler)
logger.addHandler(file_handler)