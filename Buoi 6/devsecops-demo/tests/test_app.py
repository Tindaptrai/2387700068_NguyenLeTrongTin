import importlib.util


def test_api_health_endpoint_reports_security_gates():
    assert importlib.util.find_spec("app") is not None, "app.py has not been implemented"

    from app import app

    response = app.test_client().get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "security": "gates-enabled"}