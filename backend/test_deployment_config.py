from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def test_dockerfile_uses_non_root_runtime_and_real_startup():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.13-slim" in dockerfile
    assert "COPY backend/requirements.txt" in dockerfile
    assert "uvicorn" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "USER root" not in dockerfile


def test_compose_enforces_runtime_restrictions():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["backend"]

    assert service["read_only"] is True
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["cap_drop"] == ["ALL"]
    assert "privileged" not in service
    assert "network_mode" not in service
    assert service["ports"] == ["8000:8000"]
    assert service["volumes"] == ["./data_and_demo/zeek_logs:/data/zeek_logs:ro"]
    assert service["environment"]["ENABLE_MOCK_DETECTOR"] == "false"
    assert service["environment"]["REPLAY_ON_START"] == "true"
    assert compose["networks"]["spectra_passive"]["internal"] is True


def test_compose_healthcheck_requires_readiness():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    healthcheck = compose["services"]["backend"]["healthcheck"]
    command = " ".join(str(value) for value in healthcheck["test"])

    assert "127.0.0.1:8000/health" in command
    assert "ready" in command
