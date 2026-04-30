"""
Event Analyser

- Determines whether incoming events are authorised or unauthorised
- Reads stored events from events.log
- Reads allowed behaviour from policy.json
- Determines outcome for each event
- Prints event to terminal

To be expanded:
- Alert severity levels
- Additional event types
- Dashboard integration
"""

import json
from pathlib import Path

# CONFIG
#EVENT_LOG_FILE = Path("events.log")
POLICY_FILE = Path("policy.json")


# LOAD POLICY FROM JSON
def load_policy():
	"""
	Loads policy (ruleset) from json file

	Output: Dictionary containing host mappings and detection rules
	"""
	with POLICY_FILE.open("r", encoding="utf-8") as f:
		return json.load(f)


# LOAD EVENTS FROM LOGS
def load_events():
	"""
	Loads all events from event log file.

	Assumes events.log contains one JSON object per line

	Output: Array of event dictionaries
	"""
	events = []

	if not EVENT_LOG_FILE.exists():
		return events

	with EVENT_LOG_FILE.open("r", encoding="utf-8") as f:
		for line in f:
			line = line.strip()

			if not line:
				continue

			try:
				events.append(json.loads(line))
			except json.JSONDecodeError:
				print(f"Invalid JSON line: {line}")

	return events


# DETERMINE IF EVENT IS ALLOWED
def is_event_allowed(event):
	"""
	Determines whether a given event is permitted in the policy.

	Input:
	- event: JSON object read from logs to be tested

	Output: Tuple of outcome and reason
	"""
	policy = load_policy()

	event_type = event.get("event_type")
	src_host = event.get("src_host")
	dst_ip = event.get("dst_ip")

	# Missing info
	if not event_type or not src_host or not dst_ip:
		return "Undetermined", "Missing required event fields"

	hosts = policy.get("hosts", {})
	rules = policy.get("rules", {})

	# Resolve hostname
	dst_host = None

	for hostname, ip in hosts.items():
		if ip == dst_ip:
			dst_host = hostname

	if dst_host is None:
		return "Undertermined", f"Unable to resolve hostname from IP: {dst_ip}"

	# Determine if allowed
	event_rules = rules.get(event_type)

	if event_rules is None:
		return "Undetermined", f"No rules defined for event type: {event_type}"

	allowed_destinations = event_rules.get(src_host)

	if allowed_destinations is None:
		return "Undetermined", f"No {event_type} rule defined for host: {src_host}"

	if dst_host in allowed_destinations:
		return "Authorised", f"{src_host} -> {dst_host} allowed"
	else:
		return "Unauthorised", f"{src_host} -> {dst_host} forbidden"
