from typing import Dict, Any, Optional, List
import re
import logging
from datetime import datetime
from app.detection.pattern_matcher import PatternMatcher
from app.detection.behavioral_detector import BehavioralDetector
from app.config import settings

logger = logging.getLogger(__name__)


class IntegratedScamDetector:
    """
    Integrated scam detector combining multiple detection methods:
    - Pattern matching (regex-based)
    - Behavioral analysis
    - AI review (for high-priority cases)
    """

    def __init__(self):
        self.pattern_matcher = PatternMatcher()
        self.behavioral_detector = BehavioralDetector()

    def analyze_message(
        self,
        id: str,
        account_id: str,
        message: str,
        host_number: str,
        remote_number: str,
        inserted_at: str,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a message for scam indicators

        Args:
            id: SMS message ID
            account_id: Account ID
            message: Message text
            host_number: From number
            remote_number: To number
            inserted_at: Timestamp
            **kwargs: Additional message fields

        Returns:
            Dictionary with detection results if scam detected, None otherwise
        """
        # 1. Pattern matching
        pattern_result = self.pattern_matcher.check(message)

        # 2. Behavioral analysis (placeholder - needs more context)
        behavioral_result = self.behavioral_detector.check(
            from_number=host_number,
            message_text=message,
            account_id=account_id,
        )

        # 3. Combine results and calculate risk
        is_scam = pattern_result["is_match"] or behavioral_result["is_suspicious"]

        if not is_scam:
            return None

        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(pattern_result, behavioral_result)

        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)

        # Determine detection method
        detection_method = self._determine_detection_method(
            pattern_result, behavioral_result
        )

        return {
            "sms_id": id,
            "account_id": account_id,
            "message_text": message,
            "from_number": host_number,
            "to_number": remote_number,
            "sent_at": inserted_at,
            "is_scam": True,
            "risk_level": risk_level,
            "risk_score": float(risk_score),
            "detection_method": detection_method,
            "detection_category": pattern_result.get("category")
            or behavioral_result.get("category"),
            "pattern_matched": ",".join(pattern_result.get("patterns", [])),
            "behavioral_flags": behavioral_result.get("flags", {}),
        }

    def _calculate_risk_score(
        self, pattern_result: Dict[str, Any], behavioral_result: Dict[str, Any]
    ) -> float:
        """Calculate combined risk score (0-100)"""
        score = 0.0

        # Pattern matching contribution (0-60 points)
        if pattern_result["is_match"]:
            pattern_confidence = pattern_result.get("confidence", 0.5)
            score += pattern_confidence * 60

        # Behavioral contribution (0-40 points)
        if behavioral_result["is_suspicious"]:
            behavioral_confidence = behavioral_result.get("confidence", 0.5)
            score += behavioral_confidence * 40

        return min(100.0, score)

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= settings.risk_threshold_critical * 100:
            return "CRITICAL"
        elif risk_score >= settings.risk_threshold_high * 100:
            return "HIGH"
        elif risk_score >= settings.risk_threshold_medium * 100:
            return "MEDIUM"
        else:
            return "LOW"

    def _determine_detection_method(
        self, pattern_result: Dict[str, Any], behavioral_result: Dict[str, Any]
    ) -> str:
        """Determine which detection method triggered"""
        pattern_match = pattern_result["is_match"]
        behavioral_match = behavioral_result["is_suspicious"]

        if pattern_match and behavioral_match:
            return "hybrid"
        elif pattern_match:
            return "pattern_match"
        elif behavioral_match:
            return "behavioral"
        else:
            return "unknown"
