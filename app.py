from flask import Flask, request, jsonify
print("-----------------------------------")
print("APPLICATION IS STARTING UP (DEBUG)")
print("-----------------------------------")
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

import random

@dataclass
class ExtractedIntelligence:
    bankAccounts: List[str]
    upiIds: List[str]
    phishingLinks: List[str]
    phoneNumbers: List[str]
    suspiciousKeywords: List[str]
    tactics: List[str] = None  # New Field
    scamType: str = "Unknown"  # New Field
    riskScore: int = 0         # New Field

class RiskEngine:
    """Calculates a dynamic risk score (0-100) based on accumulated indicators"""
    @staticmethod
    def calculate_score(is_scam: bool, intel: ExtractedIntelligence, message_text: str) -> int:
        score = 0
        text = message_text.lower()

        # 1. Base Score
        if is_scam: score += 30

        # 2. Hard Evidence (High Impact)
        if intel.upiIds: score += 25
        if intel.phishingLinks: score += 25
        if intel.bankAccounts: score += 25
        if intel.phoneNumbers: score += 15

        # 3. Behavioral/Tactic Indicators (Medium Impact)
        if any(t in text for t in ['urgent', 'immediately', 'block', 'suspend']): score += 10
        if any(t in text for t in ['offer', 'lottery', 'bonus', 'job']): score += 10
        
        # 4. Contextual
        if len(intel.tactics or []) > 0: score += 10

        # Cap at 100
        return min(100, score)

class ScamDetector:
    def __init__(self):
        self.scam_patterns = [
            r'account.*block', r'account.*compromised', r'account.*suspend',
            r'verify.*immediately', r'urgent.*action', r'click.*link',
            r'share.*otp', r'share.*pin', r'upi.*id', r'bank.*details',
            r'suspended.*account', r'expire.*today', r'confirm.*identity',
            r'freeze.*account', r'security.*verify', r'provide.*account.*number'
        ]
        
        self.scam_keywords = [
            'urgent', 'verify', 'blocked', 'suspended', 'expire', 'immediate',
            'click here', 'confirm', 'otp', 'upi', 'bank account', 'credit card',
            'debit card', 'atm', 'pin', 'cvv', 'security code', 'compromised',
            'freeze', 'permanently', 'act now'
        ]

    def classify_scam_type(self, text: str, intel: ExtractedIntelligence) -> str:
        """Simple rule-based classification (LLM can override later)"""
        text = text.lower()
        if intel.upiIds or 'upi' in text: return "UPI Fraud"
        if intel.bankAccounts or 'otp' in text or 'kyc' in text: return "Bank/KYC Fraud"
        if 'job' in text or 'hiring' in text: return "Job Scam"
        if 'investment' in text or 'returns' in text or 'crypto' in text: return "Investment Scam"
        if 'loan' in text or 'credit' in text: return "Loan Fraud"
        if intel.phishingLinks: return "Phishing Link"
        return "General Suspicion"
    
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
            'bankAccounts': [r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', r'\b\d{10,18}\b'],
            'upiIds': [r'\b[\w\.-]+@[\w\.-]+\b'],
            'phishingLinks': [r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'],
            'phoneNumbers': [r'\+91[-\s]?\d{10}', r'\b\d{10}\b']
        }
        
        self.tactic_keywords = {
            'Urgency': ['urgent', 'immediately', 'now', 'today', 'expire', 'deadline'],
            'Fear': ['police', 'block', 'suspend', 'arrest', 'illegal', 'fail'],
            'Greed/Reward': ['lottery', 'winner', 'bonus', 'cashback', 'prize'],
            'Authority': ['bank manager', 'police officer', 'tax department', 'fbi', 'cbi']
        }
    
    def extract_from_text(self, text: str) -> ExtractedIntelligence:
        """Extract intelligence from text"""
        intelligence = ExtractedIntelligence(
            bankAccounts=[], upiIds=[], phishingLinks=[], phoneNumbers=[], 
            suspiciousKeywords=[], tactics=[], scamType="Unknown", riskScore=0
        )
        
        # Extract using patterns
        for field, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                getattr(intelligence, field).extend(matches)
        
        # Extract suspicious keywords
        scam_keywords = ['urgent', 'verify', 'blocked', 'suspended', 'expire', 'immediate', 'otp', 'pin', 'cvv', 'account', 'bank', 'upi']
        for keyword in scam_keywords:
            if keyword.lower() in text.lower():
                intelligence.suspiciousKeywords.append(keyword)
        
        # Extract Tactics
        found_tactics = set()
        for tactic, keywords in self.tactic_keywords.items():
            if any(k in text.lower() for k in keywords):
                found_tactics.add(tactic)
        intelligence.tactics = list(found_tactics)

        # Remove duplicates
        intelligence.bankAccounts = list(set(intelligence.bankAccounts))
        intelligence.upiIds = list(set(intelligence.upiIds))
        intelligence.phishingLinks = list(set(intelligence.phishingLinks))
        intelligence.phoneNumbers = list(set(intelligence.phoneNumbers))
        intelligence.suspiciousKeywords = list(set(intelligence.suspiciousKeywords))
        
        return intelligence

import database

    def __init__(self):
        self.detector = ScamDetector()
        self.extractor = IntelligenceExtractor()
        # Initialize Database
        database.init_db()
        
        # AI Agent personas (Randomized)
        self.personas = [
            "curious_user",
            "concerned_customer", 
            "tech_naive_person",
            "elderly_victim",
            "busy_professional"
        ]
    
    def get_ai_response(self, message: str, conversation_history: List[Dict], persona: str = "curious_user") -> str:
        """Generate AI response using Groq or fallback to rule-based"""
        if groq_client == "available":
            return self._get_groq_response(message, conversation_history, persona)
        else:
            return self._get_fallback_response(message, conversation_history)
    
    def _get_groq_response(self, message: str, conversation_history: List[Dict], persona: str) -> str:
        """Generate response using Groq API with FULL CONTEXT MEMORY"""
        try:
            # Build conversation context
            system_prompt = self._build_context(persona)
            
            # Prepare messages list with System Prompt
            messages = [{"role": "system", "content": system_prompt}]
            
            # Add History (Multi-Turn Fix)
            for msg in conversation_history:
                role = "user" if msg.get('sender') == 'user' else "assistant"
                # Avoid adding system messages or metadata to the prompt flow if stored in history
                if msg.get('text'):
                     messages.append({"role": role, "content": msg['text']})
            
            # Add Current Message
            messages.append({"role": "user", "content": message})
            
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "messages": messages,
                "model": "llama-3.1-8b-instant",
                "max_tokens": 150,
                "temperature": 0.7
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
                logger.error(f"Groq API error: {response.status_code}")
                return self._get_fallback_response(message, conversation_history)
        
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return self._get_fallback_response(message, conversation_history)
    
    def _build_context(self, persona: str) -> str:
        """Build context for AI agent based on Persona"""
        persona_contexts = {
            "curious_user": "You are a cautious but curious user. Ask 1 question at a time. Never reveal you know it's a scam.",
            "concerned_customer": "You are worried about your account security. Act panicky but ask for specific verify steps. Do not expose the honeypot.",
            "tech_naive_person": "You are bad with technology. Ask what 'OTP' or 'UPI' means. Waste their time with simple questions.",
            "elderly_victim": "You are an elderly person, slow to understand. Ask them to repeat. Complain about your glasses or hearing.",
            "busy_professional": "You are in a rush. Ask for the 'bottom line'. Demand a quick fix but be skeptical."
        }
        base_instr = "\nGoal: Keep the scammer engaged as long as possible to extract UPI IDs and Phone Numbers. Be concise."
        return persona_contexts.get(persona, persona_contexts["curious_user"]) + base_instr
    
    def _get_fallback_response(self, message: str, conversation_history: List[Dict]) -> str:
        # Simple fallback (kept same)
        if 'otp' in message.lower(): return "I am not receiving the OTP. Can you send it again?"
        return "I am confused. Can you explain that clearly?"

    def _transcribe_audio(self, audio_file) -> str:
        """Transcribe audio using Groq Whisper API via direct HTTP"""
        try:
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}"
            }
            files = {
                'file': (audio_file.filename, audio_file.read(), audio_file.content_type),
                'model': (None, 'whisper-large-v3')
            }
            response = requests.post(
                "https://api.groq.com/openai/v1/audio/transcriptions",
                headers=headers,
                files=files,
                timeout=30
            )
            if response.status_code == 200:
                return response.json().get('text', '')
            return "[Audio Transcription Failed]"
        except Exception:
            return "[Audio Processing Error]"

    def process_message(self, session_id: str, message: Dict, conversation_history: List[Dict], metadata: Dict) -> Dict:
        """Process incoming message with Round 2 Features"""
        
        message_text = message.get('text', '')
        
        # Load or Create Session
        session_data = database.get_session(session_id)
        if not session_data:
            session_data = {
                'scam_detected': False,
                'total_messages': 0,
                'extracted_intelligence': ExtractedIntelligence([], [], [], [], []),
                'agent_notes': [],
                'persona': random.choice(self.personas), # Feature 8: Random Persona
                'callback_sent': False # Fix: Callback Safety
            }
            # Initial Save
            self._save_session(session_id, session_data)
        else:
            # Rehydrate Data
            self._rehydrate_session(session_data)

        session = session_data
        session['total_messages'] += 1
        
        # 1. Detect Scam & Calculate Score
        is_scam, confidence = self.detector.detect_scam(message_text)
        
        # 2. Extract Intelligence (Tactics + Data)
        current_intel = self.extractor.extract_from_text(message_text)
        self._merge_intelligence(session['extracted_intelligence'], current_intel)
        
        # 3. Dynamic Risk Scoring (Feature 3)
        risk_score = RiskEngine.calculate_score(
            session['scam_detected'] or is_scam, 
            session['extracted_intelligence'], 
            message_text
        )
        session['extracted_intelligence'].riskScore = risk_score

        # 4. Update Session State
        if is_scam and not session['scam_detected']:
            session['scam_detected'] = True
            session['extracted_intelligence'].scamType = self.detector.classify_scam_type(message_text, session['extracted_intelligence'])
            session['agent_notes'].append(f"Scam Detected: {session['extracted_intelligence'].scamType} (Conf: {confidence:.2f})")
        
        # 5. Generate Response
        response_payload = {
            "status": "success",
            "transcription": message_text if message.get('is_audio') else None
        }

        if session['scam_detected']:
            # AI Agent Reply
            ai_reply = self.get_ai_response(message_text, conversation_history, session['persona'])
            response_payload["reply"] = ai_reply
            
            # Check for Callback (Fix: Safety Check)
            if self._should_end_conversation(session) and not session.get('callback_sent'):
                self._send_final_callback(session_id, session)
                session['callback_sent'] = True
                response_payload["status"] = "completed"
        else:
            response_payload["reply"] = "I don't understand. Who is this?"

        # Save State
        self._save_session(session_id, session)
        
        return response_payload
    
    def _save_session(self, session_id, session):
        db_update = session.copy()
        db_update['extracted_intelligence'] = asdict(session['extracted_intelligence'])
        if isinstance(db_update['agent_notes'], list):
             db_update['agent_notes'] = json.dumps(db_update['agent_notes']) # Store as JSON string if DB expects it
        
        # Check if exists to decide create/update (simplified for this context)
        # Assuming database.update_session handles "upsert" or we check logical flow
        # For safety in this specific file flow:
        try:
            database.update_session(session_id, db_update)
        except:
            database.create_session(session_id, db_update)

    def _rehydrate_session(self, session_data):
        # Convert JSON strings back to Objects
        if isinstance(session_data['extracted_intelligence'], str):
             intel_dict = json.loads(session_data['extracted_intelligence'])
        else:
             intel_dict = session_data['extracted_intelligence']
        session_data['extracted_intelligence'] = ExtractedIntelligence(**intel_dict)
        
        if isinstance(session_data['agent_notes'], str):
            try:
                session_data['agent_notes'] = json.loads(session_data['agent_notes'])
            except:
                 session_data['agent_notes'] = []

    def _merge_intelligence(self, session_intel, new_intel):
        # Helper to merge lists unique
        for field in ['bankAccounts', 'upiIds', 'phishingLinks', 'phoneNumbers', 'suspiciousKeywords', 'tactics']:
            current = getattr(session_intel, field) or []
            new_items = getattr(new_intel, field) or []
            setattr(session_intel, field, list(set(current + new_items)))

    def _should_end_conversation(self, session: Dict) -> bool:
        """End if we have critical intel or hit msg limit"""
        intel = session['extracted_intelligence']
        has_critical_intel = (len(intel.bankAccounts) > 0 or len(intel.upiIds) > 0)
        return (session['total_messages'] >= 12 or (session['total_messages'] >= 6 and has_critical_intel))
    
    def _send_final_callback(self, session_id: str, session: Dict):
        """Send final results to GUVI callback endpoint"""
        try:
            payload = {
                "sessionId": session_id,
                "scamDetected": session['scam_detected'],
                "scamType": session['extracted_intelligence'].scamType, # Feature 2
                "riskScore": session['extracted_intelligence'].riskScore, # Feature 3
                "totalMessagesExchanged": session['total_messages'],
                "extractedIntelligence": asdict(session['extracted_intelligence']),
                "agentNotes": "; ".join(session['agent_notes'])
            }
            
            requests.post(
                GUVI_CALLBACK_URL,
                json=payload,
                timeout=5,
                headers={'Content-Type': 'application/json'}
            )
            logger.info(f"Callback sent for session {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to send callback for session {session_id}: {e}")

# Initialize the honeypot
honeypot = AgenticHoneypot()

def authenticate_request():
    """Authenticate API request"""
    api_key = request.headers.get('x-api-key')
    
    # Allow multipart forms to pass auth check if key is in form data
    if not api_key and request.form.get('x_api_key'):
        api_key = request.form.get('x_api_key')
        
    if not api_key or api_key != API_KEY:
        # Development mode override (optional, for easier testing)
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
    
        # Check for Audio File Upload
        audio_file = request.files.get('file') or request.files.get('audio')
        
        data = {}
        message = {}
        session_id = None
        source_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        if audio_file:
            # Handle Audio
            transcript = honeypot._transcribe_audio(audio_file)
            sender_id = f"Caller-IP:{source_ip}"
            message = {'text': transcript, 'sender': sender_id, 'is_audio': True}
            
            # Try to get other fields from form data if available
            session_id = request.form.get('sessionId')
            
        else:
            # Handle JSON
            # Parse request data with silent=True to avoid 400 if content-type is wrong
            data = request.get_json(silent=True, force=True)
            
            # If data is None (parsing failed), try to use an empty dict or parse form data
            if data is None:
                data = {}
                # Log the raw data for debugging
                logger.info(f"Raw received data: {request.data}")
            
            # Access fields with defaults
            session_id = data.get('sessionId')
            message = data.get('message')
        
        if not session_id:
            # Generate a temporary session ID if missing (for tester compatibility)
            import uuid
            safe_ip = source_ip.replace('.', '-').replace(':', '-') if source_ip else 'unknown'
            session_id = f"sess-{safe_ip}-{str(uuid.uuid4())[:8]}"
            logger.info(f"Generated temp session ID: {session_id}")
            
        # Handle cases where message might be just text or missing (for JSON flow)
        if not message and not audio_file:
            if 'text' in data:
                message = {'text': data['text'], 'sender': 'user'}
            else:
                message = {'text': 'PING_CONNECTION_TEST', 'sender': 'user'}
                
        # Ensure message is a dict
        if isinstance(message, str):
            message = {'text': message, 'sender': 'user'}
            
        conversation_history = data.get('conversationHistory', []) if isinstance(data, dict) else []
        metadata = data.get('metadata', {}) if isinstance(data, dict) else {}
        
        # Process the message
        response = honeypot.process_message(session_id, message, conversation_history, metadata)
        
        return jsonify({
            "status": "success",
            "reply": response.get('reply'),
            "transcription": response.get('transcription'),
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

@app.route('/report')
def report_portal():
    """Serve the public reporting portal (for MP3 upload)"""
    from flask import render_template
    return render_template('report.html')

@app.route('/api/stats')
def api_stats():
    """Return stats for the dashboard including Round 2 Metrics"""
    sessions = database.get_all_sessions()
    
    total_messages = 0
    scams_detected = 0
    total_intelligence = 0
    recent_logs = []
    recent_intelligence = []
    high_risk_threats = []
    
    for s in sessions:
        total_messages += s['total_messages']
        if s['scam_detected']:
            scams_detected += 1
            
        # Parse intel
        try:
            if isinstance(s['extracted_intelligence'], str):
                intel = json.loads(s['extracted_intelligence'])
            else:
                intel = s['extracted_intelligence']
        except:
            intel = {}
            
        # Count intel items & Populate Feed
        # Helpers to add unique items
        def add_intel(items, p_type):
            for i in items:
                recent_intelligence.append({"type": p_type, "value": i, "timestamp": s.get('updated_at', 'Now')})

        add_intel(intel.get('bankAccounts', []), 'BANK-ACC')
        add_intel(intel.get('upiIds', []), 'UPI-ID')
        add_intel(intel.get('phishingLinks', []), 'LINK')
        add_intel(intel.get('phoneNumbers', []), 'PHONE')
        
        count = len(intel.get('bankAccounts', []) or []) + \
                len(intel.get('upiIds', []) or []) + \
                len(intel.get('phishingLinks', []) or []) + \
                len(intel.get('phoneNumbers', []) or [])
        total_intelligence += count
        
        # Extract IP
        origin = "Unknown"
        if s['session_id'].startswith("sess-"):
            parts = s['session_id'].split('-')
            if len(parts) >= 5:
                origin = f"{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}"
        
        # Round 2 Features extraction
        scam_type = intel.get('scamType', 'Unknown')
        risk_score = intel.get('riskScore', 0)
        tactics = intel.get('tactics', [])
        
        # Add log entry
        if s['scam_detected']:
            status_icon = "🔴"
            status_text = f"THREAT DETECTED ({scam_type})"
            high_risk_threats.append({
                "origin": origin, "type": scam_type, "risk": risk_score, 
                "tactics": tactics, "time": s['updated_at']
            })
        else:
            status_icon = "🟢"
            status_text = "Monitoring"

        recent_logs.append({
            "time": s.get('updated_at', '').split('T')[1][:8] if 'T' in s.get('updated_at', '') else 'Now',
            "message": f"Source: {origin} | Status: {status_icon} {status_text} | Risk: {risk_score}",
            "is_scam": s['scam_detected'],
            "risk_score": risk_score # For UI highlighting
        })
    
    # Sort logs and intel by time (descending)
    recent_logs.sort(key=lambda x: x['time'], reverse=True)
    # Dedup intel (simple set logic not enough for list of dicts, doing basic slice)
    recent_intelligence.reverse() 
    
    # Get latest high risk threat for UI
    latest_threat = high_risk_threats[-1] if high_risk_threats else None

    return jsonify({
        "total_messages": total_messages,
        "scams_detected": scams_detected,
        "total_intelligence": total_intelligence,
        "recent_logs": recent_logs[:20],
        "recent_intelligence": recent_intelligence[:15],
        "latest_threat": latest_threat
    })

@app.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    return jsonify({"status": "healthy", "time": datetime.now().isoformat()}), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)