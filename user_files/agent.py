"""
Periodically checks host behaviour

Checked behaviour:
- Outbound TCP connections to port 22 (SSH)
- Outbound SCP connection using auditd (file transfer)

Function:
- Constructs JSON event
- Sends event data to HTTP server for processing
"""

import subprocess
import time
import json
import socket
import urllib.request
import re
from datetime import datetime, UTC

# CONFIG
SINK_URL = "http://192.168.100.10:8000"
INTERVAL = 5
HOSTNAME = socket.gethostname()

# SSH DETECTION
def get_outbound_ssh_connections():
	"""
	'ss -tn' to find established outbound TCP connections to port 22 with IP addresses

	Returns list of IPs for outbound TCP connections
	"""

	# Run Command
	result = subprocess.run(
		["ss", "-tn"],
		capture_output=True,
		text=True
	)

	# Extract Output
	lines = result.stdout.splitlines()
	connections = []

	# Extract TCP Connections
	for i in range(1, len(lines)):
		parts = lines[i].split()
		state = parts[0]
		src_port = parts[3].split(":")[1]
		dst = parts[4]

		# Check if Outbound
		if state == "ESTAB" and dst.endswith(":22"):
			ip = dst.split(":")[0]
			connections.append((ip, int(src_port)))

	return connections


# SCP TRANSFERS
def get_scp_audit_events():
	"""
	Retrieves recent scp exeuction events from audit logs using auditd

	Returns list of events
	"""
	# Run command
	result = subprocess.run(
		[
			"ausearch",
			"-k",
			"scp_exec",
			"-ts",
			"recent"],
		capture_output=True,
		text=True
	)

	lines = result.stdout.splitlines()
	events = []

	current_event_id = None

	# Extract events
	for line in lines:
		line = line.strip()

		# ID
		if "msg=audit(" in line:
			match = re.search(r":(\d+)\)", line)
			if match:
				current_event_id = match.group(1)

		# EXECVE command args
		if "type=EXECVE" in line:
			destination, port = extract_scp_dst(line)

			if destination and current_event_id:
				events.append((current_event_id, destination, port))

	return events


def extract_scp_dst(line):
	"""
	Extracts destination host IP from EXECVE audit line
	"""

	# Last argument contains dst IP
	matches = re.findall(r'a\d+="([^"]+)"', line)

	# Invalid
	if not matches:
		return None, None

	# Check if default port is changed
	port = 22
	for i, token in enumerate(matches):
		if token == "-P" and i + 1 < len(matches):
			try:
				port = int(matches[i + 1])
			except ValueError:
				pass

	dst = matches[-1]

	# Must contain ":" to be remote dst
	if ":" not in dst:
		return None, None

	host_part = dst.split(":", 1)[0]

	# Extract just the IP nost hostname
	if "@" in host_part:
		host_part = host_part.split("@", 1)[1]

	return host_part, port


# EVENT TRANSMISSION
def send_event(dst_ip, dst_port, event_type):
	"""
	Packages event data and sends to HTTP sink
	"""
	event = {
		"timestamp": datetime.now(UTC).isoformat(),
		"src_host": HOSTNAME,
		"dst_ip": dst_ip,
		"dst_port": dst_port,
		"event_type": event_type
	}

	# PACKAGE JSON
	data = json.dumps(event).encode("utf-8")

	# PACKAGE HTTP
	request = urllib.request.Request(
		SINK_URL,
		data = data,
		headers = {"Content-Type": "application/json"},
		method = "POST"
	)

	# SEND DATA
	try:
		with urllib.request.urlopen(request, timeout=5):
			print("Sent event:", event)
	except Exception as e:
		print("Failed to send event data:", e)


# MAIN LOOP
def main():
	"""
	Periodically polls (every n seconds)

	Check for outbound SSH connections, then send json data to HTTP sink
	"""
	# Existing SSH/SCP connections at startup are treated as baseline
	prev_ssh_connections = set(get_outbound_ssh_connections())
	prev_scp_events = set(get_scp_audit_events())

	print(f"Agent started on host: {HOSTNAME}")

	while True:
		# SCP - skip SSH alert if SCP detected (active on same port = false alarm)
		current_scp_events = set(get_scp_audit_events())
		new_scp_events = current_scp_events - prev_scp_events

		current_scp_dsts = set()

		for event_id, ip, port in new_scp_events:
			send_event(ip, port, "scp_transfer")
			current_scp_dsts.add(ip)

		prev_scp_events = current_scp_events

		# SSH - Only new connections
		current_ssh_connections = set(get_outbound_ssh_connections())
		new_ssh_connections = current_ssh_connections - prev_ssh_connections

		for ip, src_port in new_ssh_connections:
			if ip in current_scp_dsts:
				continue
			send_event(ip, 22, "outbound_ssh")

		prev_ssh_connections = current_ssh_connections

		time.sleep(INTERVAL)

if __name__ == "__main__":
	main()
