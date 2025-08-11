# app/hybrid_nlp.py
import os
import re

TRANSFORMERS_ENABLED = os.getenv("CTU_TRANSFORMERS", "0") == "1"
BERT_MODEL_NAME = os.getenv("CTU_BERT_MODEL", "distilbert-base-uncased")

_tokenizer = None
_model = None

RISK_PATTERNS = [
    r"verify (your|my) (account|identity)",
    r"update (your|my) (payment|billing|details)",
    r"(account|wallet) (locked|suspended|restricted)",
    r"confirm (password|security code|otp)",
    r"unusual (activity|login) detected",
    r"urgent (action|required|attention)",
    r"reset (your|my) password",
    r"payment (failed|issue|problem)",
    r"click (here|the link) to (continue|confirm|resolve|claim)",
    r"security (alert|notice|warning)",
    r"(grant|funds) (claim|apply|accept)",
]

def _init_transformers():
    global _tokenizer, _model
    if not TRANSFORMERS_ENABLED:
        return False
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        _tokenizer = AutoTokenizer.from_pretrained(BERT_MODEL_NAME)
        _model = AutoModelForSequenceClassification.from_pretrained(BERT_MODEL_NAME)
        return True
    except Exception:
        return False

def _score_with_transformers(text: str) -> float:
    try:
        import torch
        inputs = _tokenizer(text, truncation=True, max_length=256, return_tensors="pt")
        with torch.no_grad():
            logits = _model(**inputs).logits[0]
        probs = torch.softmax(logits, dim=-1).tolist()
        return float(max(probs))
    except Exception:
        return 0.0

def _score_with_regex(text: str) -> float:
    if not text: return 0.0
    text = text.lower()
    hits = sum(1 for pat in RISK_PATTERNS if re.search(pat, text))
    return min(1.0, hits / 6.0)

_initialized = False

def get_phish_context_score(text: str) -> float:
    global _initialized
    if TRANSFORMERS_ENABLED and not _initialized:
        _initialized = _init_transformers()
    if TRANSFORMERS_ENABLED and _initialized and _tokenizer and _model:
        return _score_with_transformers((text or "")[:2000])
    return _score_with_regex(text or "")
