from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class BehavioralDetector:
    """
    Behavioral-based scam detection
    Analyzes message patterns, sender behavior, and other signals
    """

    def __init__(self):
        # In production, these would be populated from database/cache
        self.known_scam_numbers = set()
        self.suspicious_patterns = {}

    def check(
        self, from_number: str, message_text: str, account_id: str
    ) -> Dict[str, Any]:
        """
        Check for behavioral scam indicators

        Args:
            from_number: Sender phone number
            message_text: Message text
            account_id: Account ID

        Returns:
            Dictionary with detection results
        """
        flags = {}
        suspicion_score = 0.0

        # Check 1: Known scam number
        if from_number in self.known_scam_numbers:
            flags["known_scammer"] = True
            suspicion_score += 0.9

        # Check 2: Message length patterns
        # Very short messages (<20 chars) with links are suspicious
        if len(message_text) < 20 and any(
            keyword in message_text.lower() for keyword in ["http", "bit.ly", "click"]
        ):
            flags["short_message_with_link"] = True
            suspicion_score += 0.6

        # Check 3: Excessive capitalization
        if len(message_text) > 10:
            caps_ratio = sum(1 for c in message_text if c.isupper()) / len(
                message_text
            )
            if caps_ratio > 0.5:
                flags["excessive_caps"] = True
                suspicion_score += 0.4

        # Check 4: Multiple exclamation marks
        exclamation_count = message_text.count("!")
        if exclamation_count >= 3:
            flags["excessive_exclamation"] = True
            suspicion_score += 0.3

        # Check 5: Suspicious keywords
        suspicious_keywords = [
            "congratulations",
            "winner",
            "free money",
            "act now",
            "limited time",
            "expires",
            "verify account",
            "suspended",
            "locked",
        ]
        keyword_matches = sum(
            1 for keyword in suspicious_keywords if keyword in message_text.lower()
        )
        if keyword_matches >= 2:
            flags["multiple_suspicious_keywords"] = True
            suspicion_score += 0.5

        # Check 6: Phone number patterns
        # Short codes (5-6 digits) are often legitimate, but some are scams
        # International numbers can be suspicious
        if len(from_number.replace("+", "").replace("-", "")) > 11:
            flags["international_number"] = True
            suspicion_score += 0.2

        # Normalize confidence (0-1)
        confidence = min(1.0, suspicion_score)
        is_suspicious = confidence >= 0.4

        if is_suspicious:
            logger.info(
                f"Behavioral flags detected: {list(flags.keys())} "
                f"(confidence: {confidence:.2f})"
            )

        return {
            "is_suspicious": is_suspicious,
            "confidence": confidence,
            "flags": flags,
            "category": "behavioral_analysis" if is_suspicious else None,
        }

    def mark_number_as_scam(self, phone_number: str):
        """Mark a phone number as a known scammer"""
        self.known_scam_numbers.add(phone_number)
        logger.info(f"Marked {phone_number} as known scam number")

    def get_sender_history(self, from_number: str) -> Dict[str, Any]:
        """
        Get historical information about a sender
        (Placeholder - would query database in production)

        Args:
            from_number: Phone number

        Returns:
            Dictionary with sender history
        """
        return {
            "total_messages": 0,
            "flagged_count": 0,
            "first_seen": None,
            "last_seen": None,
            "is_known_scammer": from_number in self.known_scam_numbers,
        }
