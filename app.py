from flask import Flask, request, jsonify
import os
import json
import re
import requests
from datetime import datetime
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import time
import threading
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Try to import Groq, handle if not available
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("Groq not available. Using fallback responses only.")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True, allow_headers="*")

# Configuration
API_KEY = os.getenv('API_KEY', 'your-secret-api-key')
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Initialize Groq client (using direct HTTP requests due to Python 3.14 compatibility)
groq_client = None
if GROQ_API_KEY:
    # Test Groq API availability
    try:
        test_response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "messages": [{"role": "user", "content": "test"}],
                "model": "llama-3.1-8b-instant",
                "max_tokens": 5
            },
            timeout=5
        )
        if test_response.status_code == 200:
            groq_client = "available"  # Flag to indicate Groq is working
            logger.info("Groq API initialized successfully via HTTP")
        else:
            logger.warning(f"Groq API test failed: {test_response.status_code}")
    except Exception as e:
        logger.warning(f"Groq API test failed: {e}")
        logger.info("Falling back to rule-based responses")

@dataclass
class ExtractedIntelligence:
    bankAccounts: List[str]
    upiIds: List[str]
    phishingLinks: List[str]
    phoneNumbers: List[str]
    suspiciousKeywords: List[str]

class ScamDetector:
    def __init__(self):
        self.scam_patterns = [
            r'account.*block',
            r'account.*compromised',
            r'account.*suspend',
            r'verify.*immediately',
            r'urgent.*action',
            r'click.*link',
            r'share.*otp',
            r'share.*pin',
            r'upi.*id',
            r'bank.*details',
            r'suspended.*account',
            r'expire.*today',
            r'confirm.*identity',
            r'freeze.*account',
            r'security.*verify',
            r'provide.*account.*number'
        ]
        
        self.scam_keywords = [
            'urgent', 'verify', 'blocked', 'suspended', 'expire', 'immediate',
            'click here', 'confirm', 'otp', 'upi', 'bank account', 'credit card',
            'debit card', 'atm', 'pin', 'cvv', 'security code', 'compromised',
            'freeze', 'permanently', 'act now'
        ]
    
    def detect_scam(self, message: str) -> Tuple[bool, float]:
        """Detect if a message is a scam and return confidence score"""
        message_lower = message.lower()
        
        # Pattern matching
        pattern_matches = sum(1 for pattern in self.scam_patterns 
                            if re.search(pattern, message_lower))
        
        # Keyword matching
        keyword_matches = sum(1 for keyword in self.scam_keywords 
                            if keyword in message_lower)
        
        # Calculate confidence score
        total_indicators = len(self.scam_patterns) + len(self.scam_keywords)
        confidence = (pattern_matches + keyword_matches) / total_indicators
        
        # Consider it a scam if confidence > 0.15 or has critical patterns
        is_scam = confidence > 0.15 or any(
            re.search(pattern, message_lower) 
            for pattern in [
                'account.*block', 'verify.*immediately', 'share.*otp', 
                'account.*compromised', 'freeze.*account', 'provide.*account.*number'
            ]
        )
        
        return is_scam, confidence

class IntelligenceExtractor:
    def __init__(self):
        self.patterns = {
            'bankAccounts': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                r'\b\d{10,18}\b'
            ],
            'upiIds': [
                r'\b[\w\.-]+@[\w\.-]+\b'
            ],
            'phishingLinks': [
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            ],
            'phoneNumbers': [
                r'\+91[-\s]?\d{10}',
                r'\b\d{10}\b'
            ]
        }
    
    def extract_from_text(self, text: str) -> ExtractedIntelligence:
        """Extract intelligence from text"""
        intelligence = ExtractedIntelligence(
            bankAccounts=[],
            upiIds=[],
            phishingLinks=[],
            phoneNumbers=[],
            suspiciousKeywords=[]
        )
        
        # Extract using patterns
        for field, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                getattr(intelligence, field).extend(matches)
        
        # Extract suspicious keywords
        scam_keywords = [
            'urgent', 'verify', 'blocked', 'suspended', 'expire', 'immediate',
            'otp', 'pin', 'cvv', 'account', 'bank', 'upi'
        ]
        
        for keyword in scam_keywords:
            if keyword.lower() in text.lower():
                intelligence.suspiciousKeywords.append(keyword)
        
        # Remove duplicates
        intelligence.bankAccounts = list(set(intelligence.bankAccounts))
        intelligence.upiIds = list(set(intelligence.upiIds))
        intelligence.phishingLinks = list(set(intelligence.phishingLinks))
        intelligence.phoneNumbers = list(set(intelligence.phoneNumbers))
        intelligence.suspiciousKeywords = list(set(intelligence.suspiciousKeywords))
        
        return intelligence

import database

class AgenticHoneypot:
    def __init__(self):
        self.detector = ScamDetector()
        self.extractor = IntelligenceExtractor()
        # Initialize Database
        database.init_db()
        
        # AI Agent personas and strategies
        self.personas = [
            "curious_user",
            "concerned_customer", 
            "tech_naive_person"
        ]
    
    def get_ai_response(self, message: str, conversation_history: List[Dict], persona: str = "curious_user") -> str:
        """Generate AI response using Groq or fallback to rule-based"""
        
        if groq_client == "available":
            return self._get_groq_response(message, conversation_history, persona)
        else:
            return self._get_fallback_response(message, conversation_history)
    
    def _get_groq_response(self, message: str, conversation_history: List[Dict], persona: str) -> str:
        """Generate response using Groq API via direct HTTP requests"""
        try:
            # Build conversation context
            context = self._build_context(conversation_history, persona)
            
            # Direct HTTP request to Groq API
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "messages": [
                    {"role": "system", "content": context},
                    {"role": "user", "content": message}
                ],
                "model": "llama-3.1-8b-instant",
                "max_tokens": 150,
                "temperature": 0.7,
                "top_p": 1,
                "stream": False
            }
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                return result["choices"][0]["message"]["content"].strip()
            else:
                logger.error(f"Groq API error: {response.status_code} - {response.text}")
                return self._get_fallback_response(message, conversation_history)
        
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return self._get_fallback_response(message, conversation_history)
    
    def _build_context(self, conversation_history: List[Dict], persona: str) -> str:
        """Build context for AI agent"""
        persona_contexts = {
            "curious_user": """You are a curious but cautious person who received a suspicious message. 
            You want to understand what's happening but are naturally inquisitive. Ask questions to gather more information.
            Never reveal that you suspect this is a scam. Act genuinely concerned about your account.""",
            
            "concerned_customer": """You are a worried customer who is concerned about your account security.
            You want to help but are asking for clarification. Show some urgency but ask for proper verification.
            Never reveal that you know this is a scam.""",
            
            "tech_naive_person": """You are not very tech-savvy and are confused by technical terms.
            Ask for simple explanations and step-by-step guidance. Show willingness to help but need clear instructions.
            Never reveal that you suspect this is a scam."""
        }
        
        return persona_contexts.get(persona, persona_contexts["curious_user"])
    
    def _get_fallback_response(self, message: str, conversation_history: List[Dict]) -> str:
        """Fallback rule-based responses"""
        message_lower = message.lower()
        
        # Response patterns based on message content
        if 'block' in message_lower or 'suspend' in message_lower:
            return "Why is my account being blocked? What did I do wrong?"
        
        elif 'verify' in message_lower or 'confirm' in message_lower:
            return "How do I verify my account? What information do you need?"
        
        elif 'upi' in message_lower:
            return "What is UPI ID? How do I find mine?"
        
        elif 'otp' in message_lower:
            return "Where will I receive the OTP? Is it safe to share?"
        
        elif 'link' in message_lower or 'click' in message_lower:
            return "Is this link safe? Can you tell me what it does first?"
        
        elif 'urgent' in message_lower or 'immediate' in message_lower:
            return "This sounds urgent. Can you help me understand what I need to do?"
        
        else:
            return "I'm not sure I understand. Can you explain this more clearly?"
    
    def process_message(self, session_id: str, message: Dict, conversation_history: List[Dict], 
                       metadata: Dict) -> Dict:
        """Process incoming message and generate response"""
        
        message_text = message.get('text', '')
        
        # Load session from DB
        session_data = database.get_session(session_id)
        
        if not session_data:
            # Create new session
            session_data = {
                'scam_detected': False,
                'total_messages': 0,
                'extracted_intelligence': ExtractedIntelligence([], [], [], [], []),
                'agent_notes': [],
                'persona': 'curious_user'
            }
            # Initial Save (convert Dataclass to dict for DB)
            db_data = session_data.copy()
            db_data['extracted_intelligence'] = asdict(session_data['extracted_intelligence'])
            database.create_session(session_id, db_data)
        else:
            # Reconstruct Dataclass from DB JSON
            # DB returns extracted_intelligence as a JSON string
            if isinstance(session_data['extracted_intelligence'], str):
                 intel_dict = json.loads(session_data['extracted_intelligence'])
            else:
                 intel_dict = session_data['extracted_intelligence']
                 
            session_data['extracted_intelligence'] = ExtractedIntelligence(**intel_dict)
            
            # Ensure agent_notes is list
            if isinstance(session_data['agent_notes'], str):
                session_data['agent_notes'] = json.loads(session_data['agent_notes'])

        
        session = session_data
        session['total_messages'] += 1
        
        # Detect scam intent
        is_scam, confidence = self.detector.detect_scam(message_text)
        
        if is_scam and not session['scam_detected']:
            session['scam_detected'] = True
            session['agent_notes'].append(f"Scam detected with confidence {confidence:.2f}")
        
        # Extract intelligence from current message
        current_intelligence = self.extractor.extract_from_text(message_text)
        
        # Merge with session intelligence
        session['extracted_intelligence'].bankAccounts.extend(current_intelligence.bankAccounts)
        session['extracted_intelligence'].upiIds.extend(current_intelligence.upiIds)
        session['extracted_intelligence'].phishingLinks.extend(current_intelligence.phishingLinks)
        session['extracted_intelligence'].phoneNumbers.extend(current_intelligence.phoneNumbers)
        session['extracted_intelligence'].suspiciousKeywords.extend(current_intelligence.suspiciousKeywords)
        
        # Remove duplicates
        for field in ['bankAccounts', 'upiIds', 'phishingLinks', 'phoneNumbers', 'suspiciousKeywords']:
            setattr(session['extracted_intelligence'], field, 
                   list(set(getattr(session['extracted_intelligence'], field))))
        
        # Generate AI response if scam detected
        if session['scam_detected']:
            ai_response = self.get_ai_response(message_text, conversation_history, session['persona'])
            
            # Check if we should end the conversation and send callback  
            should_end = self._should_end_conversation(session)
            
            # SAVE STATE TO DB
            db_update = session.copy()
            db_update['extracted_intelligence'] = asdict(session['extracted_intelligence'])
            database.update_session(session_id, db_update)

            if should_end:
                 self._send_final_callback(session_id, session)
            
            return {
                "status": "success",
                "reply": ai_response
            }
        else:
            # Not a scam, respond normally or ignore
            # Still save state (msg count updated)
            db_update = session.copy()
            db_update['extracted_intelligence'] = asdict(session['extracted_intelligence'])
            database.update_session(session_id, db_update)
            
            return {
                "status": "success", 
                "reply": "I'm sorry, I don't understand what you're referring to."
            }
    
    def _should_end_conversation(self, session: Dict) -> bool:
        """Determine if conversation should end and callback should be sent"""
        # End conversation if we have sufficient intelligence or too many messages
        intelligence = session['extracted_intelligence']
        has_intelligence = (
            len(intelligence.bankAccounts) > 0 or
            len(intelligence.upiIds) > 0 or 
            len(intelligence.phishingLinks) > 0 or
            len(intelligence.phoneNumbers) > 0
        )
        
        return (session['total_messages'] >= 10 or 
                (session['total_messages'] >= 5 and has_intelligence))
    
    def _send_final_callback(self, session_id: str, session: Dict):
        """Send final results to GUVI callback endpoint"""
        try:
            payload = {
                "sessionId": session_id,
                "scamDetected": session['scam_detected'],
                "totalMessagesExchanged": session['total_messages'],
                "extractedIntelligence": asdict(session['extracted_intelligence']),
                "agentNotes": "; ".join(session['agent_notes'])
            }
            
            response = requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            
            logger.info(f"Callback sent for session {session_id}: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Failed to send callback for session {session_id}: {e}")

# Initialize the honeypot
honeypot = AgenticHoneypot()

def authenticate_request():
    """Authenticate API request"""
    api_key = request.headers.get('x-api-key')
    if not api_key or api_key != API_KEY:
        return False
    return True

@app.route('/api/honeypot', methods=['POST', 'OPTIONS'])
def honeypot_endpoint():
    """Main honeypot API endpoint"""
    
    # Handle CORS preflight explicitly if needed (though flask-cors handles it usually)
    if request.method == 'OPTIONS':
        return jsonify({"status": "success"}), 200

    try:
        # Authenticate request
        if not authenticate_request():
             return jsonify({"error": "Unauthorized"}), 401
    
        # Parse request data with silent=True to avoid 400 if content-type is wrong
        data = request.get_json(silent=True, force=True)
        
        # If data is None (parsing failed), try to use an empty dict or parse form data
        if data is None:
            data = {}
            # Log the raw data for debugging
            logger.info(f"Raw received data: {request.data}")
        
        # Access fields with defaults
        session_id = data.get('sessionId')
        if not session_id:
            # Generate a temporary session ID if missing (for tester compatibility)
            import uuid
            session_id = f"temp-{uuid.uuid4()}"
            logger.info(f"Generated temp session ID: {session_id}")
            
        message = data.get('message')
        
        # Handle cases where message might be just text or missing
        if not message:
            # Check if there is a 'text' field directly in root (some testers do this)
            if 'text' in data:
                message = {'text': data['text'], 'sender': 'user'}
            else:
                # Create a dummy message to keep the pipeline moving if it's just a connection test
                message = {'text': 'PING_CONNECTION_TEST', 'sender': 'user'}
                
        # Ensure message is a dict
        if isinstance(message, str):
            message = {'text': message, 'sender': 'user'}
            
        conversation_history = data.get('conversationHistory', [])
        metadata = data.get('metadata', {})
        
        # Process the message
        response = honeypot.process_message(session_id, message, conversation_history, metadata)
        
        return jsonify({
            "status": "success",
            "reply": ai_response,
            "debug_headers": dict(request.headers)
        })
    
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        # DEBUG MODE: Return the error as a successful reply so the tester shows it!
        import traceback
        error_details = traceback.format_exc()
        return jsonify({
            "status": "success",
            "reply": f"DEBUG_ERROR: {str(e)}",
            "debug_headers": dict(request.headers)
        }), 200

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        "service": "Agentic Honeypot for Scam Detection",
        "version": "2.0.0",
        "endpoints": {
            "honeypot": "/api/honeypot",
            "dashboard": "/dashboard",
            "health": "/health"
        }
    })

@app.route('/dashboard')
def dashboard():
    """Serve the dashboard UI"""
    from flask import render_template
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    """Return stats for the dashboard"""
    sessions = database.get_all_sessions()
    
    total_messages = 0
    scams_detected = 0
    total_intelligence = 0
    recent_logs = []
    recent_intelligence = []
    
    for s in sessions:
        total_messages += s['total_messages']
        if s['scam_detected']:
            scams_detected += 1
            
        # Parse intel
        try:
            intel = json.loads(s['extracted_intelligence'])
        except:
            intel = {}
            
        # Count intel items
        count = (len(intel.get('bankAccounts', [])) + 
                 len(intel.get('upiIds', [])) + 
                 len(intel.get('phishingLinks', [])) + 
                 len(intel.get('phoneNumbers', [])))
        total_intelligence += count
        
        # Add to recent lists (just a few for demo)
        if len(recent_intelligence) < 10:
             for upi in intel.get('upiIds', []):
                 recent_intelligence.append({"type": "UPI", "value": upi})
             for phone in intel.get('phoneNumbers', []):
                 recent_intelligence.append({"type": "PHONE", "value": phone})
        
        # Add log entry
        recent_logs.append({
            "time": s['updated_at'].split('T')[1][:8], # HH:MM:SS
            "message": f"Session {s['session_id'][:8]}... {'(SCAM)' if s['scam_detected'] else ''}",
            "is_scam": s['scam_detected']
        })
    
    return jsonify({
        "total_messages": total_messages,
        "scams_detected": scams_detected,
        "total_intelligence": total_intelligence,
        "recent_logs": recent_logs[:20],
        "recent_intelligence": recent_intelligence[:10]
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)