"""Detector coverage: secrets, PII, storage, Python AST, and JS rules."""

from app.detectors.common import DetectContext, detect_language
from app.detectors.js_rules import detect_js
from app.detectors.python_ast import detect_python_ast
from app.models.schemas import SourceFile
from app.pipeline.detect import run_detectors


def _ctx(path, content):
    return DetectContext(path=path, language=detect_language(path), content=content, project=[SourceFile(path=path, content=content)])


def rule_ids(files):
    return {f.ruleId for f in run_detectors(files)}


def test_secret_aws_and_openai():
    code = 'AKIA_KEY = "AKIAIOSFODNN7EXAMPLE"\nkey = "sk-fake-DEADBEEF1234567890abcdef99"\n'
    ids = rule_ids([SourceFile(path="s.py", content=code)])
    assert "CM-S001" in ids
    assert "CM-S005" in ids


def test_masking_hides_value():
    code = 'key = "sk-fake-DEADBEEF1234567890abcdef99"\n'
    findings = run_detectors([SourceFile(path="s.py", content=code)])
    f = next(f for f in findings if f.ruleId == "CM-S005")
    assert "DEADBEEF" not in f.maskedValue
    assert "•" in f.maskedValue


def test_pii_ssn_and_card():
    code = 'ssn = "123-45-6789"\ncard = "4111 1111 1111 1111"\n'
    ids = rule_ids([SourceFile(path="s.py", content=code)])
    assert "CM-P003" in ids
    assert "CM-P004" in ids


def test_weak_hash_needs_password_context():
    with_pw = 'def h(password):\n    return hashlib.md5(password.encode()).hexdigest()\n'
    without = 'x = hashlib.md5(b"etag").hexdigest()\n'
    assert "CM-D002" in rule_ids([SourceFile(path="a.py", content=with_pw)])
    assert "CM-D002" not in rule_ids([SourceFile(path="b.py", content=without)])


def test_python_ast_sqli_and_shell():
    code = (
        "def f(name):\n"
        "    cur.execute('SELECT * FROM u WHERE n = ' + name)\n"
        "def g(host):\n"
        "    os.system('ping ' + host)\n"
        "eval(user_input)\n"
    )
    ids = {m.rule_id for m in detect_python_ast(code)}
    assert "CM-A001" in ids
    assert "CM-A002" in ids
    assert "CM-A003" in ids


def test_python_ast_verify_false_and_debug():
    code = "requests.get(url, verify=False)\napp.run(debug=True)\n"
    ids = {m.rule_id for m in detect_python_ast(code)}
    assert "CM-A006" in ids
    assert "CM-A005" in ids


def test_js_innerhtml_and_cors():
    code = 'el.innerHTML = "hi " + name\napp.use(cors({ origin: "*", credentials: true }))\n'
    ctx = _ctx("a.js", code)
    ids = {m.rule_id for m in detect_js(ctx)}
    assert "CM-J001" in ids
    assert "CM-J004" in ids


def test_no_false_positive_on_clean_code():
    code = "def add(a, b):\n    return a + b\n"
    assert rule_ids([SourceFile(path="clean.py", content=code)]) == set()


def test_env_template_not_flagged():
    files = [SourceFile(path=".env.example", content="API_KEY=your_api_key_here\n")]
    assert "CM-S013" not in rule_ids(files)
