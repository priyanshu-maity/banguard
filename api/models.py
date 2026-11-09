from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    investigation_id: str | None = Field(
        default=None,
        pattern=r'^[a-fA-F0-9-]{36}$'
    )

    investigation_type: Literal['url', 'message', 'combined'] = 'url'
    url: str | None = Field(default=None, max_length=2048)
    message: str | None = Field(default=None, max_length=20000)
    submit_to_blockchain: bool = False

    @model_validator(mode='after')
    def validate_investigation_input(self):
        if self.investigation_type == 'url' and not self.url:
            raise ValueError('A URL is required for a URL investigation.')

        if self.investigation_type in ('message', 'combined') and not self.message:
            raise ValueError('A message is required for a message or combined investigation.')

        if self.investigation_type == 'combined' and not self.url:
            raise ValueError('A URL is required for a combined investigation.')

        if self.url:
            try:
                parsed = urlsplit(self.url)

                if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
                    raise ValueError

                parsed.port

            except ValueError:
                raise ValueError('URL must be a valid HTTP or HTTPS URL.')

        return self
