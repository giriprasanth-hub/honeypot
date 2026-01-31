import os
import random
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

class ScamAgent:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.client = OpenAI(api_key=self.api_key) if self.api_key and OpenAI else None
        
        self.system_prompt = """
        You are 'Ramesh', a 65-year-old retired clerk. 
        Act naive, polite, and slightly greedy. 
        Waste the scammer's time with confusion and technical trouble.
        """

    def generate_response(self, incoming_message: str, history: list = None) -> str:
        """
        Generates a reply. Tries OpenAI first, falls back to the 'Scripted Library' if no key.
        """
        if not self.client:
            return self._fallback_response(incoming_message)

        try:
            # Simple simulation of history usage
            messages = [{"role": "system", "content": self.system_prompt}]
            if history: messages.extend(history)
            messages.append({"role": "user", "content": incoming_message})

            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                temperature=0.7,
                max_tokens=60
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"⚠️ LLM Error: {e}")
            return self._fallback_response(incoming_message)

    def _fallback_response(self, message: str) -> str:
        """
        The 'Scripted Library' - A massive list of naive responses to keep scammers hooked.
        """
        
        # 1. Confusion & Clarification (Wasting time asking 'Why?')
        confusion = [
            "Hello? Who is this calling?",
            "I don't understand, sir. My grandson usually handles this.",
            "Is this the main branch or the local branch?",
            "Can you speak a little louder? My hearing aid is buzzing.",
            "Wait, I thought I already paid the electricity bill?",
            "Who gave you my number? Was it Sharma ji?",
            "Sir, I am a pensioner. Please explain slowly.",
            "Ayyo! Why is the bank messaging me at this time?",
            "Is this regarding the fixed deposit maturity?",
            "I am confused. Do I need to come to the bank?"
        ]

        # 2. Technical Incompetence (Stalling by pretending to be bad at tech)
        tech_trouble = [
            "My internet is slow... the circle is just spinning...",
            "Where is the link? I cannot see blue letters.",
            "My screen is very dark. Let me get my glasses.",
            "I am clicking but nothing is happening. Is the server down?",
            "Typing is very hard on this glass screen.",
            "Can you call me instead? I cannot read small text.",
            "Battery is 2%... wait, let me find the charger...",
            "The link says '404 Error'. Did I do it wrong?",
            "Do I press the green button or the blue one?",
            "Wait, my phone is hanging. Let me restart."
        ]

        # 3. Panic & Urgency (Feigning fear to make scammer feel successful)
        panic = [
            "Oh my god! Blocked? All my pension is in there!",
            "Please do not cut my connection! I will do whatever you say.",
            "I am very scared. Will police come to my house?",
            "Sir please help me. I am alone at home.",
            "Urgent? I am panicking now. My BP is going up.",
            "Please sir, save my account. It has my daughter's wedding money.",
            "Do not lock it! I need to buy medicine today.",
            "I am trying to hurry but my hands are shaking."
        ]

        # 4. Greed & Bait (Luring them with promises of money)
        greed = [
            "Is there a fee for this? I have ₹50,000 in the account.",
            "If I verify, will I get the bonus interest you mentioned?",
            "I have a lot of savings. Is it all safe?",
            "Can I add my wife's account also? She has more money.",
            "I received a message about lottery also. Is this related?"
        ]

        # 5. The "OTP/Details" Dance (Pretending to look for info)
        otp_stalling = [
            "Where is OTP? Is it on the back of the debit card?",
            "I got a code 8... 4... wait, it disappeared.",
            "My SMS is full. Let me delete some messages first.",
            "Is the OTP the same as my PIN number?",
            "I am looking for my passbook. Please hold on...",
            "The message says 'Do not share'. Should I still share?",
            "I found a number 1234. Is that it?",
            "Let me ask my neighbor, he knows about computers."
        ]

        # Combine all lists
        all_responses = confusion + tech_trouble + panic + greed + otp_stalling
        
        # Intelligent Selection: 
        # If the incoming message has "OTP", prioritize OTP stalling.
        message = message.lower()
        if "otp" in message or "code" in message or "pin" in message:
            return random.choice(otp_stalling + confusion)
        elif "blocked" in message or "urgent" in message or "suspended" in message:
            return random.choice(panic + confusion)
        elif "click" in message or "link" in message:
            return random.choice(tech_trouble)
        
        # Otherwise, pick completely random
        return random.choice(all_responses)

agent = ScamAgent()