# Agentic Honey-Pot for Scam Detection & Intelligence Extraction

An AI-powered honeypot system that detects scam messages and autonomously engages scammers to extract actionable intelligence.

## Features

- **Scam Detection**: Advanced pattern matching and keyword analysis
- **AI Agent**: Autonomous conversational agent with multiple personas
- **Intelligence Extraction**: Extracts bank accounts, UPI IDs, phone numbers, and phishing links
- **Multi-turn Conversations**: Maintains context across conversation sessions
- **API Integration**: RESTful API with authentication and callback support

## Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Run the Application**
   ```bash
   python app.py
   ```

## API Usage

### Authentication
All requests require an API key in the header:
```
x-api-key: YOUR_SECRET_API_KEY
Content-Type: application/json
```

### Main Endpoint
```
POST /api/honeypot
```

**Request Format:**
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response Format:**
```json
{
  "status": "success",
  "reply": "Why is my account being blocked? What did I do wrong?"
}
```

## Configuration

### Environment Variables
- `API_KEY`: Your secret API key for authentication
- `GROQ_API_KEY`: Groq API key for advanced AI responses (optional but recommended)
- `PORT`: Server port (default: 5000)

### AI Agent Personas
The system uses different personas to engage scammers:
- **curious_user**: Inquisitive but cautious
- **concerned_customer**: Worried about account security
- **tech_naive_person**: Not tech-savvy, needs simple explanations

## Intelligence Extraction

The system automatically extracts:
- Bank account numbers
- UPI IDs
- Phishing links
- Phone numbers
- Suspicious keywords

## Deployment

### Local Development
```bash
python app.py
```

### Production (using Gunicorn)
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Docker (optional)
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

## Testing

Test the health endpoint:
```bash
curl http://localhost:5000/health
```

Test the main API:
```bash
curl -X POST http://localhost:5000/api/honeypot \
  -H "x-api-key: your-secret-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-session",
    "message": {
      "sender": "scammer",
      "text": "Your account will be blocked. Verify now.",
      "timestamp": 1770005528731
    },
    "conversationHistory": []
  }'
```

## Architecture

- **ScamDetector**: Pattern and keyword-based scam detection
- **IntelligenceExtractor**: Regex-based intelligence extraction
- **AgenticHoneypot**: Main orchestrator with AI agent capabilities
- **Flask API**: RESTful interface with authentication

## Security & Ethics

- No impersonation of real individuals
- No illegal instructions or harassment
- Responsible data handling
- Secure API authentication

## License

This project is for educational and research purposes only.