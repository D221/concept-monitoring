import datetime
import json
import math
import os
import sqlite3
import time

from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired

load_dotenv()
DATABASE = os.getenv("DATABASE_PATH", "db.sqlite")
COMMAND_QUEUE = {}
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "default-secret-key-for-dev")
app.config['DATABASE'] = DATABASE


TIME_RANGES_SECONDS = {
    "15m": 15 * 60,
    "1h": 60 * 60,
    "24h": 24 * 60 * 60,
    "7d": 7 * 24 * 60 * 60,
    "30d": 30 * 24 * 60 * 60,
}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # type: ignore

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

USERS = {
    ADMIN_USERNAME: {
        "password_hash": generate_password_hash(ADMIN_PASSWORD),
        "id": ADMIN_USERNAME,
    }
}


class User(UserMixin):
    def __init__(self, id):
        self.id = id

    @staticmethod
    def get(user_id):
        if user_id in USERS:
            return User(user_id)
        return None

    @staticmethod
    def check_password(user_id, password):
        user_data = USERS.get(user_id)
        if not user_data:
            return False
        return check_password_hash(user_data["password_hash"], password)


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login uses this to reload the user object from the user ID stored in the session."""
    return User.get(user_id)


class LoginForm(FlaskForm):
    """Login form definition using Flask-WTF."""

    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


def human_readable_bytes(b):
    if not isinstance(b, (int, float)) or b <= 0:
        return "0B"
    s = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(b, 1024)))
    p = math.pow(1024, i)
    return f"{round(b / p, 2)} {s[i]}"


def get_db_connection():
    conn = sqlite3.connect(app.config['DATABASE'], check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with app.app_context():
        conn = get_db_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    hostname TEXT PRIMARY KEY,
                    username TEXT,
                    cpu REAL,
                    cpu_model TEXT,
                    memory REAL,
                    total_memory INTEGER,
                    disk TEXT,
                    internal_ip TEXT,
                    external_ip TEXT,
                    network_in_rate REAL,
                    network_out_rate REAL,
                    monitored_services TEXT,
                    top_processes_by_cpu TEXT,
                    top_processes_by_memory TEXT,
                    top_processes_by_network_in TEXT,
                    top_processes_by_network_out TEXT,
                    last_seen TEXT
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL, metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL, timestamp INTEGER NOT NULL
                )""")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_metrics_history_hostname_timestamp ON metrics_history (hostname, timestamp)"
            )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
            """)
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES ('discord_webhook_url', '')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES ('cpu_threshold', '80')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES ('memory_threshold', '80')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES ('disk_threshold', '90')"
            )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_settings (
                    hostname TEXT PRIMARY KEY,
                    cpu_threshold REAL,
                    memory_threshold REAL,
                    disk_threshold REAL,
                    webhook_url TEXT,
                    webhook_rate INTEGER,
                    report_rate INTEGER
                )
            """)
            # Add global settings if not present
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES ('webhook_rate', '60')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES ('report_rate', '15')"
            )
        conn.close()


def clean_old_metrics():
    if not app.config.get('TESTING'): # Only run if not in testing mode
        conn = get_db_connection()
        cutoff = int(time.time()) - TIME_RANGES_SECONDS["30d"]
        with conn:
            deleted_rows = conn.execute(
                "DELETE FROM metrics_history WHERE timestamp < ?", (cutoff,)
            ).rowcount
        if deleted_rows > 0:
            print(f"Cleaned up {deleted_rows} old metric records.")


def send_discord_alert(message):
    conn = get_db_connection()
    webhook_url = conn.execute(
        "SELECT value FROM settings WHERE key = 'discord_webhook_url'"
    ).fetchone()["value"]
    conn.close()
    if webhook_url:
        import requests

        requests.post(webhook_url, json={"content": message})


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if User.get(username) and User.check_password(username, password):
            login_user(User.get(username))
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/report", methods=["POST"])
def report():
    data = request.json
    if data is None:
        data = {}
    hostname = data.get("hostname")
    if not hostname:
        return jsonify({"status": "error", "message": "Hostname is required"}), 400

    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM client_settings WHERE hostname = ?", (hostname,)
    ).fetchone()
    if row:
        cpu_threshold = float(row["cpu_threshold"])
        memory_threshold = float(row["memory_threshold"])
        disk_threshold = float(row["disk_threshold"])
    else:
        cpu_threshold = float(
            conn.execute(
                "SELECT value FROM settings WHERE key = 'cpu_threshold'"
            ).fetchone()["value"]
        )
        memory_threshold = float(
            conn.execute(
                "SELECT value FROM settings WHERE key = 'memory_threshold'"
            ).fetchone()["value"]
        )
        disk_threshold = float(
            conn.execute(
                "SELECT value FROM settings WHERE key = 'disk_threshold'"
            ).fetchone()["value"]
        )
    conn.close()

    alerts = []
    if data.get("cpu", 0) > cpu_threshold:
        alerts.append(
            f"⚠️ {hostname}: CPU usage {data.get('cpu')}% exceeds threshold {cpu_threshold}%"
        )
    if data.get("memory", 0) > memory_threshold:
        alerts.append(
            f"⚠️ {hostname}: Memory usage {data.get('memory')}% exceeds threshold {memory_threshold}%"
        )
    # Check disk percent for each disk
    for disk in data.get("disk", []):
        if disk.get("percent", 0) > disk_threshold:
            alerts.append(
                f"⚠️ {hostname}: Disk {disk.get('mountpoint', '')} usage {disk.get('percent')}% exceeds threshold {disk_threshold}%"
            )

    for alert in alerts:
        send_discord_alert(alert)

    conn = get_db_connection()
    with conn:
        conn.execute(
            """
                INSERT OR REPLACE INTO devices (
                    hostname, username, cpu, cpu_model, memory, total_memory, disk, 
                    internal_ip, external_ip, network_in_rate, network_out_rate, 
                    monitored_services, top_processes_by_cpu, top_processes_by_memory, 
                    top_processes_by_network_in, top_processes_by_network_out, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hostname,
                data.get("username"),
                data.get("cpu"),
                data.get("cpu_model"),
                data.get("memory"),
                data.get("total_memory"),
                json.dumps(data.get("disk")),
                data.get("internal_ip"),
                data.get("external_ip"),
                data.get("network_in_rate"),
                data.get("network_out_rate"),
                json.dumps(data.get("monitored_services")),
                json.dumps(data.get("top_processes_by_cpu")),
                json.dumps(data.get("top_processes_by_memory")),
                json.dumps(data.get("top_processes_by_network_in")),
                json.dumps(data.get("top_processes_by_network_out")),
                datetime.datetime.now().isoformat(),
            ),
        )
        current_timestamp = int(time.time())
        metrics_to_log = {
            "cpu": data.get("cpu"),
            "memory": data.get("memory"),
            "network_in": data.get("network_in_rate"),
            "network_out": data.get("network_out_rate"),
        }
        for name, value in metrics_to_log.items():
            if value is not None:
                conn.execute(
                    "INSERT INTO metrics_history (hostname, metric_name, metric_value, timestamp) VALUES (?, ?, ?, ?)",
                    (hostname, name, value, current_timestamp),
                )
    conn.close()
    return jsonify({"status": "success", "message": "Data received"}), 200


@app.route("/api/devices")
@login_required
def api_devices():
    conn = get_db_connection()
    devices_cursor = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    devices = []
    for row in devices_cursor.fetchall():
        device_dict = dict(row)
        try:
            last_seen_dt = datetime.datetime.fromisoformat(
                device_dict.get("last_seen", "").split(".")[0]
            )
            if (datetime.datetime.now() - last_seen_dt) > datetime.timedelta(minutes=3):
                device_dict["health_status"] = "down"
            else:
                device_dict["health_status"] = "up"
        except (ValueError, TypeError):
            device_dict["health_status"] = "unknown"

        total_mem = device_dict.get("total_memory")
        device_dict["total_memory_readable"] = (
            human_readable_bytes(total_mem) if total_mem else "N/A"
        )
        device_dict["network_in_readable"] = (
            human_readable_bytes(device_dict.get("network_in_rate", 0)) + "/s"
        )
        device_dict["network_out_readable"] = (
            human_readable_bytes(device_dict.get("network_out_rate", 0)) + "/s"
        )
        device_dict["disk"] = json.loads(device_dict.get("disk") or "[]")
        device_dict["monitored_services"] = json.loads(
            device_dict.get("monitored_services") or "{}"
        )
        device_dict["top_processes_by_cpu"] = json.loads(
            device_dict.get("top_processes_by_cpu") or "[]"
        )
        device_dict["top_processes_by_memory"] = json.loads(
            device_dict.get("top_processes_by_memory") or "[]"
        )
        device_dict["top_processes_by_network_in"] = json.loads(
            device_dict.get("top_processes_by_network_in") or "[]"
        )
        device_dict["top_processes_by_network_out"] = json.loads(
            device_dict.get("top_processes_by_network_out") or "[]"
        )

        for disk in device_dict["disk"]:
            disk["used_readable"] = human_readable_bytes(disk.get("used", 0))
            disk["total_readable"] = human_readable_bytes(disk.get("total", 0))

        device_dict["disk_max_percent"] = (
            max(d.get("percent", 0) for d in device_dict["disk"])
            if device_dict["disk"]
            else 0
        )
        devices.append(device_dict)
    conn.close()
    return jsonify(devices)


@app.route("/api/history/<hostname>/<metric_name>")
@login_required
def get_history(hostname, metric_name):
    if metric_name not in ["cpu", "memory", "network_in", "network_out"]:
        return jsonify({"error": "Invalid metric name"}), 400
    range_str = request.args.get("range", "24h")
    seconds_in_past = TIME_RANGES_SECONDS.get(range_str, TIME_RANGES_SECONDS["24h"])
    end_ts_seconds = int(time.time())
    start_ts_seconds = end_ts_seconds - seconds_in_past
    conn = get_db_connection()
    cursor = conn.execute(
        "SELECT timestamp, metric_value FROM metrics_history WHERE hostname = ? AND metric_name = ? AND timestamp > ? ORDER BY timestamp ASC",
        (hostname, metric_name, start_ts_seconds),
    )
    rows = cursor.fetchall()
    conn.close()
    chart_data = [
        {"x": row["timestamp"] * 1000, "y": row["metric_value"]} for row in rows
    ]
    return jsonify(
        {
            "data": chart_data,
            "min": start_ts_seconds * 1000,
            "max": end_ts_seconds * 1000,
        }
    )


@app.route("/api/command/<hostname>", methods=["POST"])
@login_required
def issue_command(hostname):
    command_data = request.json if request.json is not None else {}
    COMMAND_QUEUE[hostname] = command_data.get("command")
    return jsonify({})


@app.route("/api/command/check/<hostname>", methods=["GET"])
def check_command(hostname):
    return jsonify({"command": COMMAND_QUEUE.pop(hostname, "none")})


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    conn = get_db_connection()
    hostname = request.args.get("hostname") or request.form.get("hostname")
    devices = [
        row["hostname"]
        for row in conn.execute("SELECT hostname FROM devices").fetchall()
    ]
    selected_hostname = hostname if hostname else ""

    if request.method == "POST":
        webhook_url = request.form.get("discord_webhook_url")
        cpu_threshold = request.form.get("cpu_threshold")
        memory_threshold = request.form.get("memory_threshold")
        disk_threshold = request.form.get("disk_threshold")
        webhook_rate = request.form.get("webhook_rate")
        report_rate = request.form.get("report_rate")
        if selected_hostname:
            conn.execute(
                """
                INSERT INTO client_settings (hostname, cpu_threshold, memory_threshold, disk_threshold, webhook_url, webhook_rate, report_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hostname) DO UPDATE SET
                    cpu_threshold=excluded.cpu_threshold,
                    memory_threshold=excluded.memory_threshold,
                    disk_threshold=excluded.disk_threshold,
                    webhook_url=excluded.webhook_url,
                    webhook_rate=excluded.webhook_rate,
                    report_rate=excluded.report_rate
            """,
                (
                    selected_hostname,
                    cpu_threshold,
                    memory_threshold,
                    disk_threshold,
                    webhook_url,
                    webhook_rate,
                    report_rate,
                ),
            )
        else:
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'discord_webhook_url'",
                (webhook_url,),
            )
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'cpu_threshold'",
                (cpu_threshold,),
            )
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'memory_threshold'",
                (memory_threshold,),
            )
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'disk_threshold'",
                (disk_threshold,),
            )
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'webhook_rate'",
                (webhook_rate,),
            )
            conn.execute(
                "UPDATE settings SET value = ? WHERE key = 'report_rate'",
                (report_rate,),
            )
        conn.commit()
        flash("Settings updated successfully!", "success")
        return redirect(url_for("admin", hostname=selected_hostname))

    if selected_hostname:
        row = conn.execute(
            "SELECT * FROM client_settings WHERE hostname = ?", (selected_hostname,)
        ).fetchone()
        webhook_url = row["webhook_url"] if row else ""
        cpu_threshold = row["cpu_threshold"] if row else ""
        memory_threshold = row["memory_threshold"] if row else ""
        disk_threshold = row["disk_threshold"] if row else ""
        webhook_rate = row["webhook_rate"] if row else ""
        report_rate = row["report_rate"] if row else ""
    else:
        webhook_url = conn.execute(
            "SELECT value FROM settings WHERE key = 'discord_webhook_url'"
        ).fetchone()["value"]
        cpu_threshold = conn.execute(
            "SELECT value FROM settings WHERE key = 'cpu_threshold'"
        ).fetchone()["value"]
        memory_threshold = conn.execute(
            "SELECT value FROM settings WHERE key = 'memory_threshold'"
        ).fetchone()["value"]
        disk_threshold = conn.execute(
            "SELECT value FROM settings WHERE key = 'disk_threshold'"
        ).fetchone()["value"]
        webhook_rate = conn.execute(
            "SELECT value FROM settings WHERE key = 'webhook_rate'"
        ).fetchone()["value"]
        report_rate = conn.execute(
            "SELECT value FROM settings WHERE key = 'report_rate'"
        ).fetchone()["value"]
    conn.close()
    return render_template(
        "admin.html",
        devices=devices,
        selected_hostname=selected_hostname,
        webhook_url=webhook_url,
        cpu_threshold=cpu_threshold,
        memory_threshold=memory_threshold,
        disk_threshold=disk_threshold,
        webhook_rate=webhook_rate,
        report_rate=report_rate,
    )


@app.route("/test_webhook", methods=["POST"])
@login_required
def test_webhook():
    conn = get_db_connection()
    webhook_url = conn.execute(
        "SELECT value FROM settings WHERE key = 'discord_webhook_url'"
    ).fetchone()["value"]
    conn.close()

    if not webhook_url:
        flash("Discord webhook URL not configured.", "danger")
        return redirect(url_for("admin"))

    import requests

    data = {"content": "This is a test message from the monitoring system."}
    response = requests.post(webhook_url, json=data)

    if response.status_code == 204:
        flash("Test message sent successfully!", "success")
    else:
        flash(
            f"Failed to send test message. Status code: {response.status_code}",
            "danger",
        )

    return redirect(url_for("admin"))


@app.route("/api/report_rate/<hostname>")
def api_report_rate(hostname):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT report_rate FROM client_settings WHERE hostname = ?", (hostname,)
    ).fetchone()
    if row and row["report_rate"]:
        rate = int(row["report_rate"])
    else:
        rate = int(
            conn.execute(
                "SELECT value FROM settings WHERE key = 'report_rate'"
            ).fetchone()["value"]
        )
    conn.close()
    return jsonify({"report_rate": rate})


if __name__ == "__main__":
    init_db()
    clean_old_metrics()
    app.run(host="0.0.0.0", port=5000, debug=True)
