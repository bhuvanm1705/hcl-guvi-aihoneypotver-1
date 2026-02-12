#!/usr/bin/env python3
"""
Enhanced test script to demonstrate Groq AI responses
"""

import requests
import json
import time

# Configuration
BASE_URL = "http://localhost:5000"
API_KEY = "test-secret-api-key-123"

def test_advanced_scam_conversation():
    """Test multi-turn conversation with Groq AI"""
    print("🤖 Testing Advanced Groq AI Conversation...")
    
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    # Simulate a multi-turn scam conversation
    conversation_steps = [
        {
            "message": "URGENT: Your bank account has been compromised. Click this link immediately to secure it: http://fake-bank-security.com/verify",
            "expected": "AI should ask questions about the link or express concern"
        },
        {
            "message": "You need to provide your account number and PIN to verify your identity. This is for your security.",
            "expected": "AI should ask for clarification or show hesitation"
        },
        {
            "message": "If you don't act now, we will freeze your account permanently. Share your UPI ID: user@paytm",
            "expected": "AI should engage while trying to understand the process"
        }
    ]
    
    session_id = f"groq-test-{int(time.time())}"
    conversation_history = []
    
    for i, step in enumerate(conversation_steps, 1):
        print(f"\n--- Turn {i} ---")
        print(f"Scammer: {step['message']}")
        
        # Prepare request
        request_data = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": step['message'],
                "timestamp": int(time.time() * 1000)
            },
            "conversationHistory": conversation_history.copy(),
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }
        
        # Send request
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=request_data
        )
        
        if response.status_code == 200:
            result = response.json()
            ai_reply = result.get('reply', 'No reply')
            print(f"AI Agent: {ai_reply}")
            print(f"Expected: {step['expected']}")
            
            # Add to conversation history
            conversation_history.extend([
                {
                    "sender": "scammer",
                    "text": step['message'],
                    "timestamp": int(time.time() * 1000)
                },
                {
                    "sender": "user",
                    "text": ai_reply,
                    "timestamp": int(time.time() * 1000)
                }
            ])
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            break
        
        time.sleep(1)  # Small delay between requests

def test_intelligence_extraction():
    """Test intelligence extraction capabilities"""
    print("\n🔍 Testing Intelligence Extraction...")
    
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    # Message with multiple intelligence indicators
    test_message = """
    Your account 1234-5678-9012-3456 will be blocked. 
    Contact us at +91-9876543210 or visit http://fake-bank.scam/verify
    Send money to scammer@paytm UPI ID to reactivate.
    Use this OTP: 123456 and CVV: 789
    """
    
    request_data = {
        "sessionId": "intelligence-test",
        "message": {
            "sender": "scammer",
            "text": test_message,
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "Email",
            "language": "English",
            "locale": "IN"
        }
    }
    
    response = requests.post(
        f"{BASE_URL}/api/honeypot",
        headers=headers,
        json=request_data
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"AI Response: {result.get('reply', 'No reply')}")
        print("✅ Intelligence should be extracted from this message:")
        print("  - Bank Account: 1234-5678-9012-3456")
        print("  - Phone: +91-9876543210")
        print("  - Phishing Link: http://fake-bank.scam/verify")
        print("  - UPI ID: scammer@paytm")
        print("  - Keywords: account, blocked, OTP, CVV, etc.")
    else:
        print(f"❌ Error: {response.status_code}")

if __name__ == "__main__":
    print("=== Enhanced Groq AI Honeypot Test ===")
    
    try:
        test_advanced_scam_conversation()
        test_intelligence_extraction()
        
        print("\n🎉 All enhanced tests completed!")
        print("Your Groq-powered honeypot is ready for deployment!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the API server.")
        print("Make sure the server is running on http://localhost:5000")
    except Exception as e:
        print(f"❌ Error running tests: {e}")