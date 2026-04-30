"""
Simple Security Dashboard

Fetches alerts from logs and displays them in a human readable GUI format.

Requires login.
"""
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

# CONFIG
app = Flask(__name__)

ALERT_FILE = Path("alerts.log")

app.secret_key = "a-very-secret-secret"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = "scrypt:32768:8:1$qq2DiQ9NfRm2O5C5$dc42063cf9c8ca6dec1ab02335b7aa3852fe679effa5965bf4ab00a1a18021a8c8f1afc4664649945f1ddff556f763ac93ce164096cb9577733af8534db096ea"


# Load policy
def load_policy():
	with open("policy.json", "r", encoding="utf-8") as f:
		return json.load(f)


# Resolve Hostname from IP
def resolve_hostname(ip, host_map):
	for hostname, mapped_ip in host_map.items():
		if mapped_ip == ip:
			return hostname
	return ip


# FORMAT DATTETIME
def format_datetime(ts):
	"""
	Convert dt from ISO timestamp to human readable format

	E.g. 16 Mar 2026 14:15 UTC
	"""
	try:
		dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
		return dt.strftime("%d %b %Y %H:%M UTC")
	except Exception:
		return ts


# LOAD ALERTS
def load_alerts():
	"""
	Read alerts from logs.

	Return: List of parsed JSON alert dicts.
	"""
	alerts = []

	if not ALERT_FILE.exists():
		return alerts

	with ALERT_FILE.open("r", encoding="utf-8") as f:
		for line in f:
			line = line.strip()

			if not line:
				continue

			try:
				alert = json.loads(line)

				# Ignore already dismissed alerts
				if alert.get("dismissed"):
					continue

				alert["display_time"] = format_datetime(alert.get("timestamp", ""))
				alerts.append(alert)

			except json.JSONDecodeError:
				continue

	alerts.reverse() # Newest first
	return alerts


# Calc top offending hosts
def get_highest_offendors(alerts, limit=5):
	"""
	Count alerts coming from each host.

	Returns: List of (host, count) tuples in descending order.
	"""
	counter = Counter()

	for alert in alerts:
		src_host = alert.get("src_host")
		if src_host:
			counter[src_host] += 1

	return counter.most_common(limit)


# Calc top destination hosts
def get_highest_dests(alerts, host_map, limit=5):
	"""
	Count alerts targetted at each host.

	Resolves dest hostname.

	Returns: List of (host, count) tuples in descending order.
	"""
	counter = Counter()

	for alert in alerts:
		dst_ip = alert.get("dst_ip")
		if dst_ip:
			destination = resolve_hostname(dst_ip, host_map)
			counter[destination] += 1

	return counter.most_common(limit)


# Get evemt distribution for pie chart
def get_event_distribution(alerts):
	"""
	Get count of each active alert type.

	Returns: List of dict mapping (event type: count)
	"""
	counter = Counter()

	for alert in alerts:
		event_type = alert.get("event_type")
		if event_type:
			counter[event_type] += 1

	return dict(counter)


# ROUTES

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
	"""
	Simple admin login page. No registration - creds hardcoded.
	"""
	error=None
	if request.method == "POST":
		username = request.form.get("username", "")
		password = request.form.get("password", "")

		if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
			session["logged_in"] = True
			session["username"] = username
			return redirect(url_for("dashboard"))
		else:
			error = "Invalid username or password."
	return render_template("login.html", error=error)


# Logout
@app.route("/logout")
def logout():
	"""
	Clear session and return to login page
	"""
	session.clear()
	return redirect(url_for("login"))


# Main Dashboard Page
@app.route("/")
def dashboard():
	"""
	Dashboard to display alerts.

	Requires user to be logged in.
	"""
	if not session.get("logged_in"):
		return redirect(url_for("login"))

	alerts = load_alerts()

	policy = load_policy()
	host_map = policy.get("hosts", {})

	highest_offendors = get_highest_offendors(alerts)
	highest_dests = get_highest_dests(alerts, host_map)

	event_type_distribution = get_event_distribution(alerts)

	return render_template(
		"index.html",
		alerts=alerts,
		username=session.get("username"),
		highest_offendors=highest_offendors,
		highest_dests=highest_dests,
		event_type_distribution = event_type_distribution
	)

# Dismissing an Alert
@app.route("/dismiss/<alert_id>", methods=["POST"])
def dismiss_alert(alert_id):
	"""
	Mark an alert as dismissed so it doesn't show on web page
	"""

	updated_lines = []

	# Search for alert to dismiss
	with ALERT_FILE.open("r", encoding="utf-8") as f:
		for line in f:
			try:
				alert = json.loads(line)

				if alert.get("alert_id") == alert_id:
					alert["dismissed"] = True

				updated_lines.append(json.dumps(alert))

			except:
				updated_lines.append(line.strip())

	# Rewrite alerts
	with ALERT_FILE.open("w", encoding="utf-8") as f:
		for line in updated_lines:
			f.write(line + "\n")

	return redirect(url_for("dashboard"))


# Dsimiss all Alerts
@app.route("/dismiss-all", methods=["POST"])
def dismass_all_alerts():
	"""
	Mark all alerts as dismissed to clear web page.
	"""

	updated_lines=[]

	# Copy all logs and mark as dismissed
	with ALERT_FILE.open("r", encoding="utf-8") as f:
		for line in f:
			try:
				alert = json.loads(line)

				if not alert.get("dismissed"):
					alert["dismissed"] = True

				updated_lines.append(json.dumps(alert))

			except:
				updated_lines.append(line.strip())

	with ALERT_FILE.open("w", encoding="utf-8") as f:
		for line in updated_lines:
			f.write(line + "\n")

	return redirect(url_for("dashboard"))

# Main init
if __name__ == "__main__":
	app.run(host="0.0.0.0", port=5000)
