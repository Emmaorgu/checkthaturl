import importlib
app_mod = importlib.import_module("app")

def test_legit_has_no_phish_only_reasons():
    feats = {"is_new_domain":0,"suspicious_tld":0,"phish_context_score":0.0}
    verdict = app_mod.guarded_verdict(0.05, feats, behavior_score=0.0)
    assert verdict == "Legitimate"
