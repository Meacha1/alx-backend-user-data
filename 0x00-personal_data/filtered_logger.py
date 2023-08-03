#!/usr/bin/env python3
"""Filtered Logger Module

This module contains classes and functions for logging and
filtering sensitive information in log messages.

"""

import re
from typing import List
import logging
import mysql.connector
import os


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class

    This class is responsible for formatting log records
    and obfuscating sensitive information.

    Attributes:
        REDACTION (str): The string to use for redacting sensitive information.
        FORMAT (str): The log format string.
        SEPARATOR (str): The separator character used in log messages.

    Args:
        fields (List[str]): A list of field names to be
        obfuscated in log messages.

    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with obfuscated sensitive information.

        Args:
            record (logging.LogRecord): The log record to be formatted.

        Returns:
            str: The formatted log record with obfuscated
            sensitive information.

        """
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


PII_FIELDS = ("name", "email", "password", "ssn", "phone")


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Get MySQL database connection.

    This function obtains the MySQL database connection using the credentials
    provided as environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection: The database
        connection object.

    """
    db_connect = mysql.connector.connect(
        user=os.getenv('PERSONAL_DATA_DB_USERNAME', 'root'),
        password=os.getenv('PERSONAL_DATA_DB_PASSWORD', ''),
        host=os.getenv('PERSONAL_DATA_DB_HOST', 'localhost'),
        database=os.getenv('PERSONAL_DATA_DB_NAME')
    )
    return db_connect


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """Obfuscate sensitive information in log messages using regex.

    This function replaces occurrences of certain field
    values with the provided redaction.

    Args:
        fields (List[str]): A list of field names to be obfuscated.
        redaction (str): The string to use for obfuscating the field values.
        message (str): The log message to be filtered.
        separator (str): The separator character used in log messages.

    Returns:
        str: The log message with obfuscated sensitive information.

    """
    for field in fields:
        message = re.sub(f'{field}=(.*?){separator}',
                         f'{field}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """Get a logging.Logger object with a redacting formatter.

    This function returns a logging.Logger object with
    the specified log level and a redacting formatter.

    Returns:
        logging.Logger: The configured Logger object.

    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    target_handler = logging.StreamHandler()
    target_handler.setLevel(logging.INFO)

    formatter = RedactingFormatter(list(PII_FIELDS))
    target_handler.setFormatter(formatter)

    logger.addHandler(target_handler)
    return logger


def main() -> None:
    """Main function to retrieve and log data from the users table.

    This function obtains a database connection,
    retrieves all rows from the users table,
    and logs each row under a filtered format.

    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    headers = [field[0] for field in cursor.description]
    logger = get_logger()

    for row in cursor:
        info_answer = ''
        for f, p in zip(row, headers):
            info_answer += f'{p}={(f)}; '
        logger.info(info_answer)

    cursor.close()
    db.close()


if __name__ == '__main__':
    main()
