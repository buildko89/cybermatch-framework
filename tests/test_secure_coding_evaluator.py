"""Phase 6 detection, scoring, immutable results and asset contracts."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
yaml = pytest.importorskip("yaml")

from cybermatch.defense import SecureCodingEvaluator
from cybermatch.defense.secure_coding_evaluator import PENALTIES, PHASES, RULES
from cybermatch.models.secure_coding import (
    KillChainPhase, SecureCodingAuditResult, VulnerabilityCategory as Category,
)

ROOT = Path(__file__).resolve().parents[1]


def audit(code, filename='snippet.py'):
    return SecureCodingEvaluator().audit_code(code, filename)


@pytest.mark.parametrize('query', ['f"SELECT * FROM users WHERE id={value}"',
                                  '"SELECT * FROM users WHERE id=%s" % value',
                                  '"SELECT {}".format(value)', '"SELECT " + value'])
def test_sqli_detection(query):
    result = audit(f'cursor.execute({query})')
    assert result.findings[0].category == Category.SQLI
    assert result.findings[0].asvs_requirement == 'V5.3.4'
    assert result.asvs_score == pytest.approx(.7)
    assert not audit('cursor.execute("SELECT * FROM users WHERE id=?", (value,))').findings
    assert not audit('User.objects.filter(name=value)').findings


def test_xss_detection():
    assert audit('mark_safe(value)').findings[0].category == Category.XSS
    assert audit('from django.utils.safestring import mark_safe as safe\nsafe(value)').findings
    assert audit('Environment(autoescape=False)').findings
    assert not audit('# mark_safe(value)\nx = "mark_safe(value)"').findings


@pytest.mark.parametrize('template', ['{{ value | safe }}', '{% autoescape off %}{{ value }}{% endautoescape %}',
                                    '{% autoescape false %}{{ value }}{% endautoescape %}'])
def test_template_xss(template):
    assert audit(template, 'page.html').findings[0].category == Category.XSS
    assert audit('template = ' + repr(template)).findings[0].category == Category.XSS
    assert not audit('{{ value }}', 'page.html').findings


def test_csrf_exempt_detection():
    result = audit('@csrf_exempt\ndef view(request):\n    pass')
    assert result.findings[0].category == Category.CSRF
    assert result.findings[0].line_number == 1


@pytest.mark.parametrize('source', [
    'requests.get(url)', 'requests.get(url=request.GET["url"])',
    'import requests as r\nr.get(url)',
    'from urllib.request import urlopen as open_url\nopen_url(url)',
    'url = request.GET["url"]\nrequests.get(url)',
    'def view(url):\n    requests.get(url)',
    'requests.get("http://169.254.169.254/latest/meta-data/")',
])
def test_ssrf_detection(source):
    assert audit(source).findings[0].category == Category.SSRF
    assert not audit('requests.get("https://example.com", timeout=5)').findings


def test_idor_detection_and_scoping():
    assert audit('User.objects.get(id=request.GET["id"])').findings[0].category == Category.IDOR_BOLA
    assert audit('uid=request.GET["id"]\nUser.objects.get(pk=uid)').findings
    assert not audit('Record.objects.get(id=request.GET["id"], owner=request.user)').findings
    # Mere authentication does not authorize arbitrary objects.
    assert audit('assert request.user.is_authenticated\nUser.objects.get(id=request.GET["id"])').findings


def test_command_injection():
    assert audit('import os\nos.system(command)').findings[0].category == Category.COMMAND_INJECTION
    assert audit('subprocess.run(command, shell=True)').findings
    assert not audit('subprocess.run(["tool", "--", value], shell=False)').findings


def test_clean_code_full_score():
    result = audit('cursor.execute("SELECT * FROM users WHERE id = ?", (value,))')
    assert result.asvs_score == 1.0
    assert result.findings == result.mitigated_killchain_phases == ()
    assert audit('').asvs_score == 1.0


@pytest.mark.parametrize('code,filename', [(None, 'snippet.py'), (123, 'snippet.py'),
    ([], 'snippet.py'), ('pass', None), ('pass', ''), ('pass', 123),
    ('def broken(', 'snippet.py'), ('\x00', 'snippet.py'), ('pass', '\x00')])
def test_invalid_inputs(code, filename):
    with pytest.raises(ValueError):
        audit(code, filename)


def test_score_floor_phases_and_evidence():
    result = audit('\n'.join('cursor.execute(f"SELECT {value}")' for _ in range(8)))
    assert result.asvs_score == 0.0
    assert len(result.findings) == 8
    assert result.mitigated_killchain_phases == (KillChainPhase.EXPLOITATION,)
    assert all(f.matched_text and f.description and f.remediation_guide for f in result.findings)
    with pytest.raises(FrozenInstanceError):
        result.findings[0].line_number = 99


@pytest.mark.parametrize('score', [-1, 2, float('nan'), float('inf'), None, '1', True])
def test_result_score_validation(score):
    with pytest.raises(ValueError):
        SecureCodingAuditResult((), score, ())


def test_scope_and_assignment_resolution():
    assert audit('query=f"SELECT {value}"\ncursor.execute(query)').findings
    assert audit('url="https://example.com"\ndef view(url):\n    requests.get(url)').findings
    assert audit('url=request.GET["url"]\ndef other():\n    url="https://example.com"\nrequests.get(url)').findings


def test_yaml_assets_consistency():
    profile = yaml.safe_load((ROOT / 'profiles/owasp_asvs_web_defense.yaml').read_text(encoding='utf-8'))
    matrix = yaml.safe_load((ROOT / 'scenarios/killchain_attack_defense_matrix.yaml').read_text(encoding='utf-8'))
    assert profile['standard_version'] == '4.0.3'
    assert set(profile['sections']) == {'V4', 'V5', 'V13', 'V14'}
    requirements = {r['id'] for section in profile['sections'].values() for r in section['requirements']}
    assert {check['requirement'] for check in profile['checks']} <= requirements
    assert profile['scoring']['penalties'] == {key.value: value for key, value in PENALTIES.items()}
    assert {c['category'] for c in profile['checks']} == set(Category)
    for check in profile['checks']:
        severity, requirement, _, _ = RULES[Category(check['category'])]
        assert (check['severity'], check['requirement']) == (severity.value, requirement)
    assert [phase['phase'] for phase in matrix['phases']] == [p.value for p in KillChainPhase]
    for phase in matrix['phases']:
        assert set(phase['controls']) == set(matrix['controls'])
        assert phase['attack_tactics'] and phase['attack']
    assert matrix['remediation_phase_mapping'] == {c.value: [p.value for p in phases] for c, phases in PHASES.items()}


def test_recursion_limit_and_binop_chains():
    with pytest.raises(ValueError, match='code must be valid Python or use a template filename'):
        audit('x=' + '+'.join(["\'a\'"] * 1000))


def test_visitor_recursion_error_is_normalized(monkeypatch):
    from cybermatch.defense.secure_coding_evaluator import _Scanner

    def fail_visit(self, node):
        raise RecursionError('visitor recursion')

    monkeypatch.setattr(_Scanner, 'visit', fail_visit)
    with pytest.raises(ValueError) as error:
        audit('pass')
    assert isinstance(error.value.__cause__, RecursionError)


@pytest.mark.parametrize('source', [
    'q="SELECT "\nq += value\ncursor.execute(q)',
    'if flag:\n    q=f"SELECT {value}"\nelse:\n    q="SELECT 1"\ncursor.execute(q)',
    'q=value\nq="SELECT 1"\ncursor.execute(q)',
    'q=value\ncopy=q\nq="SELECT 1"\ncursor.execute(copy)',
    'q: str="SELECT "\nq += value\ncursor.execute(q)',
])
def test_augassign_and_branch_taint_sqli(source):
    assert Category.SQLI in {f.category for f in audit(source).findings}


@pytest.mark.parametrize('source', [
    'pool.execute(value)', 'r.raw(value)',
    'q="SELECT "\nq += "1"\ncursor.execute(q)',
    'q="SELECT 1"\ndef other():\n    q=value\ncursor.execute(q)',
])
def test_false_positive_reduction(source):
    assert audit(source).asvs_score == 1.0


@pytest.mark.parametrize('source', [
    'endpoints={"status": "https://api.example.com/status"}\nrequests.get(endpoints[choice], timeout=5, allow_redirects=False)',
    'requests.get({"status": "https://api.example.com/status"}[choice])',
    'User.objects.get(id=request.GET["id"], id__in=authorized_user_ids(request.user))',
    'User.objects.filter(pk=request.GET["id"], id__in=request.user.authorized_ids).first()',
])
def test_remediation_guidance_clean_score(source):
    assert audit(source).asvs_score == 1.0


@pytest.mark.parametrize('source,category', [
    ('get_object_or_404(User, pk=request.GET["id"])', Category.IDOR_BOLA),
    ('User.objects.filter(id=request.GET["id"]).first()', Category.IDOR_BOLA),
    ('requests.Session().get(request.GET["url"])', Category.SSRF),
    ('session.get(url)', Category.SSRF),
    ('s=requests.Session()\ns.get(url)', Category.SSRF),
    ('from markupsafe import Markup as html\nhtml(value)', Category.XSS),
    ('Markup(value)', Category.XSS),
    ('eval(value)', Category.COMMAND_INJECTION),
    ('import pickle as p\np.loads(value)', Category.COMMAND_INJECTION),
    ('pool.execute(f"SELECT {value}")', Category.SQLI),
    ('r.raw(query=value)', Category.SQLI),
    ('conn.execute(value)', Category.SQLI),
    ('endpoints={"status": url}\nrequests.get(endpoints[choice])', Category.SSRF),
])
def test_extended_vulnerabilities(source, category):
    assert category in {f.category for f in audit(source).findings}
