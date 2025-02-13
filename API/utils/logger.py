import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logger(
    logger_name: str = "logger",
    log_file: str = "app.log",
    level: int = logging.DEBUG,
    max_bytes: int = 1_000_000,  # 1 MB per file
    
):

    logger = logging.getLogger(logger_name)
    logger.setLevel(level)

    if not logger.handlers:
        # Create a rotating file handler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=5 # 5 files max (5MB)
        )
        """This should be avoid in larger apps but for this example is ok -> Maybe solved as talked in the first interview
            with some sort of S3 almacenation with partitions and a cron job that stores old logs in a NAS so we can reduce the cost of the S3 storage"""
        file_handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s - - %(levelname)s - - %(funcName)s() -  %(message)s"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

   
    return logger

logger = setup_logger()
