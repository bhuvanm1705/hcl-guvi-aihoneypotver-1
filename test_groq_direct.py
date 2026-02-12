#!/usr/bin/env python3
"""
Test Groq API directly with HTTP requests
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv()

def test_groq_api():
    """Test Groq API with direct HTTP request"""
    
    api_key = os.getenv('GROQ_API_KEY')
    if not api_key:
        print("❌ No GROQ_API_KEY found in environment")
        return False
    
    print(f"🔑 Using API Key: {api_key[:20]}...")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "messages": [
            {"role": "user", "content": "Say hello in exactly 5 words"}
        ],
        "model": "llama-3.1-8b-instant",
        "max_tokens": 20,
        "temperature": 0.7
    }
    
    try:
        print("🚀 Testing Groq API...")
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=10
        )
        
        print(f"📊 Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result["choices"][0]["message"]["content"].strip()
            print(f"✅ Groq Response: '{ai_response}'")
            return True
        else:
            print(f"❌ Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False

if __name__ == "__main__":
    print("=== Testing Groq API Directly ===")
    success = test_groq_api()
    
    if success:
        print("\n🎉 Groq API is working! Your honeypot will use AI responses.")
    else:
        print("\n⚠️  Groq API failed. Your honeypot will use fallback responses.")
        print("   (This is still fine for the hackathon!)")