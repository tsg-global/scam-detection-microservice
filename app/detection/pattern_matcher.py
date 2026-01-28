import re
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class PatternMatcher:
    """
    Pattern-based scam detection using regex patterns
    Matches known scam patterns in message text
    """

    def __init__(self):
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load scam patterns organized by category

        Returns:
            Dictionary of pattern categories with regex patterns
        """
        return {
            "phishing": [
                {
                    "pattern": r"(verify|confirm|update).*account",
                    "confidence": 0.7,
                    "description": "Account verification request",
                },
                {
                    "pattern": r"click.*link|click.*here",
                    "confidence": 0.6,
                    "description": "Suspicious link request",
                },
                {
                    "pattern": r"suspend(ed)?.*account",
                    "confidence": 0.8,
                    "description": "Account suspension threat",
                },
            ],
            "financial_fraud": [
                {
                    "pattern": r"(won|win|prize|lottery|claim)",
                    "confidence": 0.7,
                    "description": "Prize/lottery scam",
                },
                {
                    "pattern": r"(urgent|immediate).*payment",
                    "confidence": 0.8,
                    "description": "Urgent payment request",
                },
                {
                    "pattern": r"(refund|owe|owed).*(\$|dollar|money)",
                    "confidence": 0.7,
                    "description": "Fake refund/owed money",
                },
                {
                    "pattern": r"(bank|credit card).*expir",
                    "confidence": 0.8,
                    "description": "Banking credential expiry",
                },
            ],
            "social_engineering": [
                {
                    "pattern": r"(act now|limited time|expires soon)",
                    "confidence": 0.6,
                    "description": "Urgency tactics",
                },
                {
                    "pattern": r"(free|gift|offer).*claim",
                    "confidence": 0.5,
                    "description": "Free offer claim",
                },
                {
                    "pattern": r"(tax|IRS|government).*owe",
                    "confidence": 0.9,
                    "description": "Government impersonation",
                },
            ],
            "authentication_theft": [
                {
                    "pattern": r"verification code|one.time.password|OTP|2FA code",
                    "confidence": 0.6,
                    "description": "Authentication code request",
                },
                {
                    "pattern": r"(enter|provide|send).*code",
                    "confidence": 0.5,
                    "description": "Code sharing request",
                },
            ],
            "package_delivery": [
                {
                    "pattern": r"package.*delivery|parcel.*waiting",
                    "confidence": 0.7,
                    "description": "Fake delivery notification",
                },
                {
                    "pattern": r"(USPS|UPS|FedEx|DHL).*redelivery",
                    "confidence": 0.8,
                    "description": "Courier impersonation",
                },
            ],
        }

    def check(self, message: str) -> Dict[str, Any]:
        """
        Check message against known scam patterns

        Args:
            message: The SMS message text

        Returns:
            Dictionary with match results
        """
        message_lower = message.lower()
        matched_patterns = []
        max_confidence = 0.0
        category = None

        for cat, patterns in self.patterns.items():
            for pattern_dict in patterns:
                pattern = pattern_dict["pattern"]
                confidence = pattern_dict["confidence"]
                description = pattern_dict["description"]

                if re.search(pattern, message_lower, re.IGNORECASE):
                    matched_patterns.append(description)
                    if confidence > max_confidence:
                        max_confidence = confidence
                        category = cat

        is_match = len(matched_patterns) > 0

        if is_match:
            logger.info(
                f"Pattern match found: {category} "
                f"(confidence: {max_confidence}, patterns: {len(matched_patterns)})"
            )

        return {
            "is_match": is_match,
            "category": category,
            "confidence": max_confidence,
            "patterns": matched_patterns,
        }

    def add_pattern(
        self, category: str, pattern: str, confidence: float, description: str
    ):
        """
        Dynamically add a new pattern (for learning)

        Args:
            category: Pattern category
            pattern: Regex pattern string
            confidence: Confidence score (0-1)
            description: Human-readable description
        """
        if category not in self.patterns:
            self.patterns[category] = []

        self.patterns[category].append(
            {
                "pattern": pattern,
                "confidence": confidence,
                "description": description,
            }
        )
        logger.info(f"Added new pattern to category '{category}': {description}")
