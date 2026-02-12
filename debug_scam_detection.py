#!/usr/bin/env python3
"""
Debug scam detection
"""

import sys
sys.path.append('.')
from app import ScamDetector

def test_scam_detection():
    detector = ScamDetector()
    
    test_messages = [
        "URGENT: Your bank account has been compromised. Click this link immediately",
        "You need to provide your account number and PIN to verify your identity",
        "If you don't act now, we will freeze your account permanently",
        "Your account will be blocked today. Verify immediately.",
        "Hello, how are you doing today?"
    ]
    
    for msg in test_messages:
        is_scam, confidence = detector.detect_scam(msg)
        print(f"Message: {msg[:50]}...")
        print(f"Scam: {is_scam}, Confidence: {confidence:.3f}")
        print()

if __name__ == "__main__":
    test_scam_detection()