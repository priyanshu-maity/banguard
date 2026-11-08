import re


class InputSanitizer:
    MAX_LENGTH = 10000

    CONTROL_CHAR_PATTERN = re.compile(
        r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'
    )

    DEFANGED_URL_PATTERN = re.compile(
        r'hxxps?://',
        re.IGNORECASE
    )

    DEFANGED_DOT_PATTERN = re.compile(
        r'\[\.\]'
    )

    @classmethod
    def sanitize(cls, message: str) -> str:

        if not isinstance(message, str):
            raise TypeError('Message must be a string.')

        message = message[:cls.MAX_LENGTH]
        message = cls.CONTROL_CHAR_PATTERN.sub('', message)
        message = cls.DEFANGED_URL_PATTERN.sub(
            lambda match: match.group().replace('hxxp', 'http'),
            message
        )

        message = cls.DEFANGED_DOT_PATTERN.sub('.', message)

        return message.strip()
