import anthropic
from typing import Dict, Any, Optional
import logging
from app.config import settings

logger = logging.getLogger(__name__)


class AnthropicClient:
    """Client for interacting with the Anthropic Claude API"""

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        self.model = settings.anthropic_model

    async def analyze_scam(
        self, message_text: str, current_detection: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze a message for scam patterns using Claude

        Args:
            message_text: The SMS message text to analyze
            current_detection: Current detection category (if any)

        Returns:
            Dictionary with analysis results
        """
        try:
            prompt = f"""Analyze this SMS message for scam indicators.

Message: "{message_text}"
Current Detection Category: {current_detection or "None"}

Provide a JSON response with:
1. is_scam: boolean - is this likely a scam?
2. confidence: float (0-1) - confidence in the assessment
3. scam_type: string - type of scam (phishing, social engineering, financial fraud, etc.)
4. risk_indicators: array - specific red flags found
5. new_pattern_detected: boolean - is this a new pattern not commonly seen?
6. pattern_regex: string - if new pattern, suggest a regex pattern (or null)
7. reasoning: string - brief explanation

Respond with valid JSON only."""

            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            # Parse the response
            response_text = message.content[0].text
            logger.info(f"Claude analysis complete for message")

            # In production, you'd want to parse this as JSON
            # For now, return a mock structure
            return {
                "is_scam": True,
                "confidence": 0.85,
                "scam_type": "phishing",
                "risk_indicators": ["urgency language", "suspicious link"],
                "new_pattern_detected": False,
                "pattern_regex": None,
                "reasoning": response_text,
            }

        except Exception as e:
            logger.error(f"Failed to analyze message with Claude: {e}")
            return {
                "is_scam": None,
                "confidence": 0.0,
                "error": str(e),
            }

    async def generate_summary(
        self,
        total_scams: int,
        scams_by_risk: Dict[str, int],
        false_positive_rate: float,
    ) -> str:
        """
        Generate a daily summary report using Claude

        Args:
            total_scams: Total number of scams detected
            scams_by_risk: Dictionary of risk level counts
            false_positive_rate: False positive rate

        Returns:
            Summary text
        """
        try:
            prompt = f"""Generate a concise daily summary report for scam detection.

Statistics:
- Total scams detected: {total_scams}
- By risk level: {scams_by_risk}
- False positive rate: {false_positive_rate:.2%}

Provide:
1. Key findings (2-3 bullet points)
2. Notable trends
3. Recommended actions (if any)

Keep it brief and actionable."""

            message = self.client.messages.create(
                model=self.model,
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )

            summary = message.content[0].text
            logger.info("Claude generated daily summary")
            return summary

        except Exception as e:
            logger.error(f"Failed to generate summary with Claude: {e}")
            return f"Error generating summary: {str(e)}"
