import re

class IntelligenceExtractor:
    def __init__(self):
        # Regex patterns specifically tuned for Indian banking context
        self.patterns = {
            # Matches standard UPI IDs (e.g., name@okicici, user@paytm)
            "upi_id": r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}",
            
            # Matches Indian mobile numbers (starts with 6-9, optional +91)
            "phone_number": r"(?:\+91[\-\s]?)?[6-9]\d{9}",  
            
            # Matches http and https links
            "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*",
            
            # Matches standard numeric bank account numbers (9-18 digits)
            "bank_account": r"\b\d{9,18}\b",
            
            # Matches Indian Financial System Code (4 chars, 0, 6 chars)
            "ifsc": r"[A-Z]{4}0[A-Z0-9]{6}"
        }

    def extract(self, text: str) -> dict:
        """
        Scans text and returns unique extracted entities in a dictionary.
        """
        intelligence = {
            "upi_ids": [],
            "phishing_links": [],
            "phone_numbers": [],
            "bank_accounts": [],
            "ifsc_codes": []
        }

        # 1. Extract UPI IDs
        intelligence["upi_ids"] = list(set(re.findall(self.patterns["upi_id"], text)))

        # 2. Extract URLs
        intelligence["phishing_links"] = list(set(re.findall(self.patterns["url"], text)))

        # 3. Extract Phone Numbers
        intelligence["phone_numbers"] = list(set(re.findall(self.patterns["phone_number"], text)))
        
        # 4. Extract Potential Bank Accounts
        # We perform a filter to avoid confusing phone numbers (10 digits) with accounts
        raw_numbers = re.findall(self.patterns["bank_account"], text)
        clean_accounts = []
        for num in raw_numbers:
            # Simple heuristic: Accounts usually aren't exactly 10 digits (phones are)
            # Unless they are specifically labeled as accounts (context checking is advanced/next-step)
            if len(num) != 10:
                clean_accounts.append(num)
        
        intelligence["bank_accounts"] = list(set(clean_accounts))

        # 5. Extract IFSC
        intelligence["ifsc_codes"] = list(set(re.findall(self.patterns["ifsc"], text)))

        return intelligence

# Create the singleton instance
extractor = IntelligenceExtractor()