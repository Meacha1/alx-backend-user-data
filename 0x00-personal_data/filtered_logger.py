#!/usr/bin/env python3
'''regex to obfuscate sensitive information'''

import re
from typing import List

def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Obfuscates sensitive fields in the log message.

    Arguments:
    fields: a list of strings representing all fields to obfuscate
    redaction: a string representing by what the field will be obfuscated
    message: a string representing the log line
    separator: a string representing by which character is separating all fields in the log line (message)

    Returns:
    The log message with sensitive fields obfuscated.
    """
    regex_pattern = '|'.join(f'({field}=.*?)({separator}|$)' for field in fields)
    return re.sub(regex_pattern, f'{redaction}\\2', message)
