import importlib
app_mod = importlib.import_module("app")

def test_guarded_verdict_surface_only_downgrades():
    feats = {
        "is_new_domain": 1, "has_https": 0, "suspicious_tld": 1,
        "non_surface_red_flags": 0, "phish_context_score": 0.0
    }
    v = app_mod.guarded_verdict(0.9, feats, behavior_score=0.0)
    assert v in ("Suspicious","Legitimate")

def test_category_weights_less_surface_bias():
    feats = {"suspicious_tld":1,"is_new_domain":1,"domain_entropy":0.0,
             "content_red_flags":0,"phish_context_score":0.0}
    scores = app_mod.compute_category_scores(feats, behavior_score=0.0)
    assert scores["content"] <= 0.01
    assert 0.2 <= scores["domain"] <= 0.8
