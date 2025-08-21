import math
import importlib

def _reload_with(monkeypatch, **env):
    # Reload the module so it picks up new env vars
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    import app.services.calibration as calib
    return importlib.reload(calib)

def test_calibrate_probability_identity_default(monkeypatch):
    calib = _reload_with(monkeypatch, CTU_CALIB_A="1.0", CTU_CALIB_B="0.0")
    # With A=1,B=0 calibration should be identity (within tiny epsilon)
    samples = [0.01, 0.1, 0.3, 0.5, 0.8, 0.99]
    for p in samples:
        pc = calib.calibrate_probability(p)
        assert abs(pc - p) < 1e-6, f"expected ~identity for p={p}, got {pc}"

def test_verdict_from_calibrated_thresholds_env(monkeypatch):
    calib = _reload_with(
        monkeypatch,
        CTU_THRESH_LEGIT_MAX="0.25",
        CTU_THRESH_PHISH_MIN="0.75",
        CTU_CALIB_A="1.0",
        CTU_CALIB_B="0.0",
    )
    assert calib.verdict_from_calibrated(0.20) == "Legitimate"
    assert calib.verdict_from_calibrated(0.50) == "Suspicious"
    assert calib.verdict_from_calibrated(0.80) == "Phishing"

def test_reliability_bands(monkeypatch):
    calib = _reload_with(monkeypatch, CTU_CALIB_A="1.0", CTU_CALIB_B="0.0")
    cases = [
        (0.05, "Very Low", 0.05),
        (0.25, "Low", 0.10),
        (0.50, "Medium", 0.18),
        (0.70, "High", 0.25),
        (0.90, "Very High", 0.30),
    ]
    for p, band, err in cases:
        info = calib.reliability_info(p)
        assert info["band"] == band
        assert math.isclose(info["expected_error_rate"], err, rel_tol=0, abs_tol=1e-9)

def test_apply_contradiction_guards_bump_legit_on_hard_signals(monkeypatch):
    calib = _reload_with(monkeypatch)
    verdict, p = calib.apply_contradiction_guards(
        verdict="Legitimate",
        p_cal=0.20,
        features={"has_password_field": 1, "phish_context_score": 0.0, "timer_urgency_score": 0.0},
        behavior={"events": [], "post_action_redirects_form": 0},
        structure={"score": 0.10, "template": ""},
        legal_ok=False,
    )
    assert verdict == "Suspicious"
    assert p == 0.20  # probability is not altered by guards

def test_apply_contradiction_guards_soften_phishing_when_legal_ok(monkeypatch):
    calib = _reload_with(monkeypatch)
    verdict, p = calib.apply_contradiction_guards(
        verdict="Phishing",
        p_cal=0.82,
        features={"has_password_field": 0, "phish_context_score": 0.10, "timer_urgency_score": 0.0},
        behavior={"events": [], "post_action_redirects_form": 0},
        structure={"score": 0.20, "template": ""},
        legal_ok=True,
    )
    assert verdict == "Suspicious"
    assert p == 0.82

def test_calibrate_probability_is_clipped(monkeypatch):
    # Extreme A/B still yields [0,1] bounds
    calib = _reload_with(monkeypatch, CTU_CALIB_A="3.0", CTU_CALIB_B="2.0")
    assert 0.0 <= calib.calibrate_probability(0.000001) <= 1.0
    assert 0.0 <= calib.calibrate_probability(0.999999) <= 1.0
