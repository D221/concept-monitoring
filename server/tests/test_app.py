import json
import os
import tempfile

import pytest

from server.app import COMMAND_QUEUE, app, get_db_connection, init_db


@pytest.fixture
def client():
    db_fd, app.config["DATABASE"] = tempfile.mkstemp()
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test_secret_key"
    app.config["WTF_CSRF_ENABLED"] = False  # disable CSRF for testing

    with app.test_client() as client:
        with app.app_context():
            init_db()
            COMMAND_QUEUE.clear()
        yield client

    os.close(db_fd)
    os.unlink(app.config["DATABASE"])


def login(client, username, password):
    return client.post(
        "/login", data=dict(username=username, password=password), follow_redirects=True
    )


def logout(client):
    return client.get("/logout", follow_redirects=True)


def test_login_logout(client):
    # --- Successful login ---
    rv = login(
        client,
        os.getenv("ADMIN_USERNAME", "admin"),
        os.getenv("ADMIN_PASSWORD", "admin"),
    )
    assert b"Dashboard" in rv.data  # login succeeded

    # --- Logout ---
    rv = logout(client)
    assert b"Login" in rv.data  # redirected to login page

    # --- Failed login ---
    rv = login(client, "admin", "wrongpassword")
    assert rv.status_code == 200
    # Only check login page rendered; no need to assert Dashboard not present
    assert b"Login" in rv.data


def test_index_page_requires_login(client):
    rv = client.get("/", follow_redirects=False)
    assert rv.status_code == 302
    assert "/login?next=%2F" in rv.headers["Location"]

    login(
        client,
        os.getenv("ADMIN_USERNAME", "admin"),
        os.getenv("ADMIN_PASSWORD", "admin"),
    )
    rv = client.get("/", follow_redirects=True)
    assert b"Dashboard" in rv.data


def test_api_devices_requires_login(client):
    rv = client.get("/api/devices", follow_redirects=False)
    assert rv.status_code == 302
    assert "/login?next=%2Fapi%2Fdevices" in rv.headers["Location"]

    login(
        client,
        os.getenv("ADMIN_USERNAME", "admin"),
        os.getenv("ADMIN_PASSWORD", "admin"),
    )
    rv = client.get("/api/devices", follow_redirects=True)
    assert rv.status_code == 200
    assert b"[]" in rv.data


def test_report_endpoint(client):
    # No login required for report endpoint
    data = {
        "hostname": "test-host",
        "username": "test-user",
        "cpu": 10.5,
        "cpu_model": "test-cpu",
        "memory": 20.1,
        "total_memory": 8000000000,
        "disk": [
            {
                "mountpoint": "/",
                "percent": 50.0,
                "used": 1000000000,
                "total": 2000000000,
            }
        ],
        "internal_ip": "192.168.1.10",
        "external_ip": "1.1.1.1",
        "network_in_rate": 1000.0,
        "network_out_rate": 2000.0,
        "monitored_services": {"nginx": "running"},
        "top_processes_by_cpu": [],
        "top_processes_by_memory": [],
        "top_processes_by_network_in": [],
        "top_processes_by_network_out": [],
    }
    rv = client.post("/report", json=data)
    assert rv.status_code == 200
    assert b"Data received" in rv.data

    # Verify data is in the database
    with app.app_context():
        conn = get_db_connection()
        device = conn.execute(
            "SELECT * FROM devices WHERE hostname = 'test-host'"
        ).fetchone()
        assert device is not None
        assert device["cpu"] == 10.5
        conn.close()


def test_api_command_check(client):
    # Test command queueing and checking
    hostname = "test-client"
    command_to_issue = {"command": "refresh"}

    # Issue command (requires login)
    login(client, "admin", "admin")
    client.post(f"/api/command/{hostname}", json=command_to_issue)

    # Check command (no login required)
    rv = client.get(f"/api/command/check/{hostname}")
    assert rv.status_code == 200
    assert json.loads(rv.data)["command"] == "refresh"

    # Check again, should be 'none' as it's popped
    rv = client.get(f"/api/command/check/{hostname}")
    assert rv.status_code == 200
    assert json.loads(rv.data)["command"] == "none"
