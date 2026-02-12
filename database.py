import sqlite3
import json
import os
from datetime import datetime
from dataclasses import asdict

DB_NAME = "honeypot.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Create sessions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            created_at TEXT,
            updated_at TEXT,
            scam_detected BOOLEAN,
            scam_confidence REAL,
            total_messages INTEGER,
            extracted_intelligence TEXT,
            agent_notes TEXT,
            persona TEXT,
            conversation_context TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_session(session_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return dict(row)
    return None

def create_session(session_id, initial_data):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    now = datetime.now().isoformat()
    
    c.execute('''
        INSERT INTO sessions (
            session_id, created_at, updated_at, scam_detected, 
            scam_confidence, total_messages, extracted_intelligence, 
            agent_notes, persona, conversation_context
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        session_id,
        now,
        now,
        initial_data.get('scam_detected', False),
        initial_data.get('scam_confidence', 0.0),
        initial_data.get('total_messages', 0),
        json.dumps(initial_data.get('extracted_intelligence', {})),
        json.dumps(initial_data.get('agent_notes', [])),
        initial_data.get('persona', 'curious_user'),
        json.dumps(initial_data.get('conversation_context', []))
    ))
    conn.commit()
    conn.close()

def update_session(session_id, data):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    now = datetime.now().isoformat()
    
    # We only update fields that are present in data
    # But for simplicity in this hackathon, we usually pass the full state
    
    c.execute('''
        UPDATE sessions SET
            updated_at = ?,
            scam_detected = ?,
            scam_confidence = ?,
            total_messages = ?,
            extracted_intelligence = ?,
            agent_notes = ?,
            persona = ?,
            conversation_context = ?
        WHERE session_id = ?
    ''', (
        now,
        data.get('scam_detected'),
        data.get('scam_confidence'),
        data.get('total_messages'),
        json.dumps(data.get('extracted_intelligence')),
        json.dumps(data.get('agent_notes')),
        data.get('persona'),
        json.dumps(data.get('conversation_context', [])),
        session_id
    ))
    conn.commit()
    conn.close()

def get_all_sessions():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM sessions ORDER BY updated_at DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]
