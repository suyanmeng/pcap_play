import logging

def log_init():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    fmt = '%(asctime)s %(filename)s %(levelname)s  %(funcName)s  %(message)s'
    format = logging.Formatter(fmt)
    sh = logging.StreamHandler()
    logger.addHandler(sh)
    sh.setFormatter(format)
    fh = logging.FileHandler('log.log', encoding='utf-8')
    logger.addHandler(fh)
    fh.setFormatter(format)

def log():
    return logging.getLogger()
