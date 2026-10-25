"""The built UI is served from the backend origin without changing the API contract."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.ui_static import install_ui

from ._netguard import block_non_loopback  # noqa: F401


def _app(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<html>cm-ui</html>", encoding="utf-8")
    (tmp_path / "assets" / "a.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "favicon.png").write_bytes(b"png")
    app = FastAPI()

    @app.get("/")
    def root():
        return {"app": "Chaos Monkey"}

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    assert install_ui(app, tmp_path) is True
    return TestClient(app, base_url="http://127.0.0.1:8000")


def test_browser_gets_index_api_client_gets_json(tmp_path):
    c = _app(tmp_path)
    assert "cm-ui" in c.get("/", headers={"accept": "text/html,application/xhtml+xml"}).text
    assert c.get("/", headers={"accept": "application/json"}).json() == {"app": "Chaos Monkey"}
    assert c.get("/assets/a.js").status_code == 200
    assert c.get("/favicon.png").content == b"png"
    assert c.get("/api/health").json() == {"status": "ok"}


def test_no_dist_is_a_noop(tmp_path):
    assert install_ui(FastAPI(), tmp_path / "missing") is False
