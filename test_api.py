#!/usr/bin/env python3
"""
Test script for the Agentic Honeypot API
"""

import requests
import json
import time

# Configuration
BASE_URL = "http://localhost:5000"
API_KEY = "test-secret-api-key-123"

def test_health():
    """Test health endpoint"""
    print("Testing health endpoint...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()

def test_scam_detection():
    """Test scam detection with sample messages"""
    print("Testing scam detection...")
    
    # Test cases
    test_cases = [
        {
            "sessionId": "test-session-1",
            "message": {
                "sender": "scammer",
                "text": "Your bank account will be blocked today. Verify immediately.",
                "timestamp": int(time.time() * 1000)
            },
            "conversationHistory": [],
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        },
        {
            "sessionId": "test-session-1", 
            "message": {
                "sender": "scammer",
                "text": "Share your UPI ID to avoid account suspension.",
                "timestamp": int(time.time() * 1000)
            },
            "conversationHistory": [
                {
                    "sender": "scammer",
                    "text": "Your bank account will be blocked today. Verify immediately.",
                    "timestamp": int(time.time() * 1000)
                },
                {
                    "sender": "user", 
                    "text": "Why is my account being blocked?",
                    "timestamp": int(time.time() * 1000)
                }
            ],
            "metadata": {
                "channel": "SMS",
                "language": "English", 
                "locale": "IN"
            }
        }
    ]
    
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Message: {test_case['message']['text']}")
        
        response = requests.post(
            f"{BASE_URL}/api/honeypot",
            headers=headers,
            json=test_case
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            result = response.json()
            print(f"Reply: {result.get('reply', 'No reply')}")
        else:
            print(f"Error: {response.text}")
        print()

def test_non_scam():
    """Test with non-scam message"""
    print("Testing non-scam message...")
    
    test_case = {
        "sessionId": "test-session-2",
        "message": {
            "sender": "friend",
            "text": "Hey, how are you doing today?",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "WhatsApp",
            "language": "English",
            "locale": "IN"
        }
    }
    
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    response = requests.post(
        f"{BASE_URL}/api/honeypot",
        headers=headers,
        json=test_case
    )
    
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print(f"Reply: {result.get('reply', 'No reply')}")
    else:
        print(f"Error: {response.text}")
    print()

def test_authentication():
    """Test API authentication"""
    print("Testing authentication...")
    
    # Test without API key
    response = requests.post(f"{BASE_URL}/api/honeypot", json={})
    print(f"Without API key - Status: {response.status_code}")
    
    # Test with wrong API key
    headers = {"x-api-key": "wrong-key", "Content-Type": "application/json"}
    response = requests.post(f"{BASE_URL}/api/honeypot", headers=headers, json={})
    print(f"With wrong API key - Status: {response.status_code}")
    print()

if __name__ == "__main__":
    print("=== Agentic Honeypot API Test ===\n")
    
    try:
        test_health()
        test_authentication()
        test_scam_detection()
        test_non_scam()
        
        print("All tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the API server.")
        print("Make sure the server is running on http://localhost:5000")
    except Exception as e:
        print(f"Error running tests: {e}")