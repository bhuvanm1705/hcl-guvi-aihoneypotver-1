import re

class ExtractedIntelligence:
    def __init__(self, bankAccounts, upiIds, phishingLinks, phoneNumbers, suspiciousKeywords, tactics, scamType, riskScore):
        self.bankAccounts = bankAccounts
        self.upiIds = upiIds
        self.phishingLinks = phishingLinks
        self.phoneNumbers = phoneNumbers
        self.suspiciousKeywords = suspiciousKeywords
        self.tactics = tactics
        self.scamType = scamType
        self.riskScore = riskScore

class IntelligenceExtractor:
    def __init__(self):
        self.patterns = {
            'bankAccounts': [r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', r'\b\d{10,18}\b'],
            'upiIds': [r'\b[\w\.-]+@[\w\.-]+\b'],
            'phishingLinks': [r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'],
            'phoneNumbers': [r'\+91[-\s]?\d{10}', r'\b\d{10}\b']
        }
    
    def extract_from_text(self, text: str) -> ExtractedIntelligence:
        intelligence = ExtractedIntelligence(
            bankAccounts=[], upiIds=[], phishingLinks=[], phoneNumbers=[], 
            suspiciousKeywords=[], tactics=[], scamType="Unknown", riskScore=0
        )
        
        print(f"DEBUG: Analyzing text: '{text}'")
        for field, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    print(f"DEBUG: Found {field}: {matches} using pattern {pattern}")
                    getattr(intelligence, field).extend(matches)
        return intelligence

extractor = IntelligenceExtractor()
text = "Pay 500 to scammer@okicici or call 9876543210 immediately."
intel = extractor.extract_from_text(text)

print("-" * 20)
print(f"UPIs Found: {len(intel.upiIds)}")
print(f"Phones Found: {len(intel.phoneNumbers)}")
print(f"Total Items: {len(intel.upiIds) + len(intel.phoneNumbers) + len(intel.bankAccounts) + len(intel.phishingLinks)}")
