import os
import json
from dotenv import load_dotenv

from groq import Groq

from .analysis_result import MessageAnalysisResult
from .system_prompt import SYSTEM_PROMPT


load_dotenv()

class LanguageAnalyzer:
    GROQ_API_KEY = os.getenv('GROQ_API_KEY')

    SIGNALS = [
        'urgency',
        'fear_or_threat',
        'authority_impersonation',
        'financial_manipulation',
        'credential_requests',
        'reward_or_prize_lure',
        'secrecy_or_isolation'
    ]

    def __init__(self, message: str, result: MessageAnalysisResult, client: Groq | None = None):
        self.message = message
        self.result = result

        self.client = client or Groq(api_key=self.GROQ_API_KEY)

    def analyze(self) -> MessageAnalysisResult:
        response = self.client.chat.completions.create(
            model='openai/gpt-oss-120b',
            messages=[
                {
                    'role': 'system',
                    'content': SYSTEM_PROMPT
                },
                {
                    'role': 'user',
                    'content': self.message
                }
            ],
            response_format={
                'type': 'json_object'
            },
            temperature=0,
            max_tokens=1500
        )

        content = response.choices[0].message.content

        if not content:
            raise ValueError('Groq returned an empty response.')

        data = json.loads(content)

        self._store_signals(data)
        self._store_claimed_brand(data)

        return self.result

    def _store_signals(self, data: dict):
        for signal in self.SIGNALS:
            signal_data = data.get(signal, {})
            detected = signal_data.get('detected', False)
            evidence = signal_data.get('evidence', [])

            # Retain only exact snippets from the original message
            evidence = [
                snippet
                for snippet in evidence
                if isinstance(snippet, str)
                and snippet in self.message
            ]

            detected = bool(detected and evidence)

            setattr(
                self.result,
                signal,
                (detected, evidence)
            )

    def _store_claimed_brand(self, data: dict):
        brand = data.get('claimed_brand')

        if isinstance(brand, str) and brand.strip():
            self.result.claimed_brand = brand.strip()
