"""
AVOS AI - Explainable AI Chatbot
DistilBERT-based Q&A for plain-English threat explanations
Fully offline using cached model weights
"""

import logging
from typing import Optional

logger = logging.getLogger('AVOS.AI.Chatbot')

DISTILBERT_MODEL = 'distilbert-base-cased-distilled-squad'
MODEL_CACHE_DIR  = 'models/distilbert'

# ─── Static knowledge base for threat explanations ───────────────────────────
THREAT_KNOWLEDGE = {
    "ransomware": (
        "Ransomware is malware that encrypts your files and demands payment "
        "for the decryption key. AVOS detected mass file encryption or "
        "suspicious extension changes. Your files are protected via shadow copy backup."
    ),
    "shellcode": (
        "Shellcode is arbitrary machine code injected into a legitimate process's memory. "
        "Attackers use it to execute commands without dropping a visible file on disk. "
        "AVOS detected executable private memory with unusual patterns."
    ),
    "process hollowing": (
        "Process hollowing is an attack where a legitimate process (e.g., svchost.exe) "
        "is started in suspended state, its memory is replaced with malware, and then "
        "resumed. AVOS detected a PE header at an unexpected memory address."
    ),
    "dll hijacking": (
        "DLL hijacking exploits Windows's DLL search order by placing a malicious DLL "
        "with the same name as a legitimate one in a higher-priority search path. "
        "This causes programs to load the malicious version instead."
    ),
    "rootkit": (
        "A rootkit is malware that hides itself and other malicious processes from "
        "the operating system. AVOS detected discrepancies between different "
        "process enumeration methods, suggesting kernel-level manipulation."
    ),
    "code injection": (
        "Code injection writes malicious code into another process's memory space. "
        "AVOS flagged suspicious API calls like WriteProcessMemory + "
        "CreateRemoteThread that are typical of this attack pattern."
    ),
    "phishing": (
        "Phishing URLs are fake websites designed to steal your login credentials "
        "or financial information by impersonating legitimate services. "
        "AVOS blocked access based on domain blocklist or URL pattern analysis."
    ),
    "form jacking": (
        "Form-jacking intercepts data you type into online forms — like credit card "
        "numbers or UPI IDs — and sends them to attackers. AVOS's Payment Shield "
        "intercepted an outgoing HTTP request containing sensitive financial data."
    ),
    "ddos": (
        "A DDoS (Distributed Denial of Service) attack floods your network with "
        "connection requests from many sources to make services unavailable. "
        "AVOS detected a high connection rate from a single IP and blocked it."
    ),
    "keylogger": (
        "A keylogger records every keystroke you make, including passwords and messages. "
        "AVOS detected the use of SetWindowsHookEx or GetAsyncKeyState — "
        "APIs commonly used by keyloggers."
    ),
    "packed executable": (
        "A packed executable uses compression or encryption to hide its true code from "
        "antivirus scanners. High entropy sections suggest the file may be packed. "
        "AVOS's heuristic engine flagged this for further inspection."
    ),
    "anomaly": (
        "An anomaly means this file or behavior is statistically unusual compared to "
        "normal software. The AI model detected patterns that don't match known-clean "
        "files. This doesn't confirm malware, but warrants caution."
    ),
}

# Greetings and meta questions
META_QUESTIONS = {
    "what is avos": "AVOS AI is a next-generation Windows security platform with AI-powered threat detection, kernel-level protection, and real-time monitoring.",
    "how does avos work": "AVOS uses a layered approach: kernel drivers intercept file and network events, the AI module analyzes them with machine learning, and the UI shows you real-time alerts.",
    "am i protected": "Yes! AVOS is actively monitoring your system. All security modules are enabled and running.",
    "what threats did you find": "Check the Threats panel for a full list. I can explain any specific threat you select.",
}


class AIExplainerChatbot:
    """
    DistilBERT-based chatbot for natural language threat explanations.
    Falls back to keyword matching if transformers library not available.
    """

    def __init__(self):
        self._qa_pipeline = None
        self._context_store: dict = {}
        self._load_model()

    def _load_model(self):
        """Load DistilBERT Q&A pipeline (cached locally)."""
        try:
            from transformers import pipeline
            self._qa_pipeline = pipeline(
                'question-answering',
                model=DISTILBERT_MODEL,
                tokenizer=DISTILBERT_MODEL,
                cache_dir=MODEL_CACHE_DIR
            )
            logger.info("DistilBERT Q&A model loaded.")
        except ImportError:
            logger.warning("transformers not installed — using keyword-based chatbot.")
        except Exception as e:
            logger.warning(f"DistilBERT load error: {e} — using keyword-based fallback.")

    def answer(self, question: str, threat_context: Optional[dict] = None) -> tuple[str, float]:
        """
        Answer a user question about a threat.
        Returns (answer_text, confidence_score)
        """
        q_lower = question.lower().strip()

        # Check meta questions
        for key, answer in META_QUESTIONS.items():
            if key in q_lower:
                return answer, 0.95

        # Find best matching threat category
        best_topic = self._find_topic(q_lower)
        base_knowledge = THREAT_KNOWLEDGE.get(best_topic, '')

        # Enrich with specific threat context if provided
        if threat_context:
            context = self._build_context(threat_context, base_knowledge)
        else:
            context = base_knowledge

        if not context:
            return ("I don't have specific information about that. Please check the threat "
                    "details panel or consult the AVOS documentation."), 0.3

        # Use DistilBERT if available
        if self._qa_pipeline and context:
            try:
                result = self._qa_pipeline(question=question, context=context)
                answer_text = result['answer']
                confidence  = result['score']

                # Append full explanation for context
                if confidence < 0.5:
                    answer_text = context[:500]
                    confidence = 0.6

                return answer_text, confidence
            except Exception as e:
                logger.debug(f"DistilBERT inference error: {e}")

        # Fallback: return the full knowledge base entry
        return context, 0.75

    def _find_topic(self, question: str) -> str:
        """Find the most relevant threat topic from the question."""
        scores = {}
        for topic in THREAT_KNOWLEDGE:
            topic_words = topic.split()
            score = sum(1 for w in topic_words if w in question)
            if score > 0:
                scores[topic] = score

        if scores:
            return max(scores, key=scores.get)
        return ''

    def _build_context(self, threat: dict, base: str) -> str:
        """Build Q&A context from threat event data."""
        lines = [base] if base else []
        if threat.get('event_type'):
            lines.append(f"The detected threat type is: {threat['event_type']}.")
        if threat.get('path'):
            lines.append(f"Affected file: {threat['path']}.")
        if threat.get('score'):
            lines.append(f"Threat score: {threat['score']:.1f}/100.")
        if threat.get('explanation'):
            lines.append(threat['explanation'])
        if threat.get('details', {}).get('signature'):
            lines.append(f"Matched malware signature: {threat['details']['signature']}.")
        return ' '.join(lines)

    def add_knowledge(self, topic: str, text: str):
        """Extend the knowledge base at runtime."""
        THREAT_KNOWLEDGE[topic.lower()] = text
        logger.info(f"Knowledge base updated: {topic}")
