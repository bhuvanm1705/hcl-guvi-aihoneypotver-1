import unittest
import sys
import os
import json
from unittest.mock import MagicMock, patch

# Mock database module before importing app
sys.modules['database'] = MagicMock()
sys.modules['flask'] = MagicMock()
sys.modules['flask_cors'] = MagicMock()
sys.modules['requests'] = MagicMock()
sys.modules['dotenv'] = MagicMock()

# Mock env vars
os.environ['API_KEY'] = 'test-key'
os.environ['GROQ_API_KEY'] = 'test-groq-key'

# Import app logic - must patch imports that happen at module level
with patch.dict(sys.modules, {'flask': MagicMock(), 'flask_cors': MagicMock(), 'requests': MagicMock()}):
      from app import AgenticHoneypot, ExtractedIntelligence, RiskEngine

class TestHoneypotLogic(unittest.TestCase):
    def setUp(self):
        self.honeypot = AgenticHoneypot()
        
    def test_callback_trigger_strict(self):
        # Create a mock session
        session = {
            'total_messages': 0,
            'scam_detected': False,
            'extracted_intelligence': ExtractedIntelligence(
                bankAccounts=[], upiIds=[], phishingLinks=[], phoneNumbers=[], 
                suspiciousKeywords=[], tactics=[], scamType="Unknown", riskScore=0
            ),
            'agent_notes': [],
            'callback_sent': False,
            'persona': 'curious_user'
        }
        
        # Test Case: 2 Intel Items
        message = "Pay 500 to scammer@okicici or call +91 9876543210 immediately."
        
        # 1. Detect & Score
        is_scam, conf = self.honeypot.detector.detect_scam(message)
        
        # 2. Extract
        current_intel = self.honeypot.extractor.extract_from_text(message)
        
        # 3. Merge
        self.honeypot._merge_intelligence(session['extracted_intelligence'], current_intel)
        
        # 4. Check Count
        intel = session['extracted_intelligence']
        count = len(intel.upiIds) + len(intel.phoneNumbers) + len(intel.phishingLinks) + len(intel.bankAccounts)
        print(f"DEBUG: Count = {count}")
        print(f"DEBUG: UPIs = {intel.upiIds}")
        print(f"DEBUG: Phones = {intel.phoneNumbers}")
        
        self.assertGreaterEqual(count, 2, "Intel count should be at least 2")
        
        # 5. Check Callback
        should_end = self.honeypot._should_end_conversation(session)
        self.assertTrue(should_end, "Callback trigger (Intel >= 2) failed")

if __name__ == '__main__':
    unittest.main()
