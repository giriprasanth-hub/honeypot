import os
import random
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

class ScamAgent:
    def __init__(self):
        # Checks for API Key in environment variables
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.client = OpenAI(api_key=self.api_key) if self.api_key and OpenAI else None
        
        # The Persona: A naive, slightly greedy, elderly person
        self.system_prompt = """
        You are 'Ramesh', a 65-year-old retired clerk living in Pune. 
        You are not very tech-savvy but you are polite and slightly greedy.
        
        A scammer has just messaged you. 
        Your Goal: Keep them engaged as long as possible. Waste their time.
        
        Guidelines:
        1. Act naive. Ask simple questions ("What is OTP?", "How do I click?").
        2. Show interest but pretend to have technical trouble.
        3. NEVER reveal you are an AI.
        4. Keep responses short (under 20 words), like a real SMS/WhatsApp user.
        5. Occasionally make typos.
        """

    def generate_response(self, incoming_message: str, history: list = None) -> str:
        """
        Generates a reply to the scammer.
        If no API key is found, returns a simulated response.
        """
        if not self.client:
            return self._fallback_response(incoming_message)

        messages = [{"role": "system", "content": self.system_prompt}]
        
        # Add conversation history if exists
        if history:
            messages.extend(history)
            
        messages.append({"role": "user", "content": incoming_message})

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo", # Cheap and fast for Hackathons
                messages=messages,
                temperature=0.7,
                max_tokens=60
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"⚠️ LLM Error: {e}")
            return self._fallback_response(incoming_message)

    def _fallback_response(self, message: str) -> str:
        """Backup responses if API is down/missing (For Demo Reliability)"""
        responses = [
            "Hello? Who is this?",
            "I don't understand, sir. My grandson usually handles this.",
            "Is there a fee? I am a pensioner.",
            "My internet is slow, please wait...",
            "Can you call me instead? Typing is hard."
        ]
        return random.choice(responses)

agent = ScamAgent()