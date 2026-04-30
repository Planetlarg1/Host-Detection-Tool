"""
HTTP event collector

- Listens for HTTP POST requests on port 8000
- Will recive a JSON body explaining an event
- Appends events to events.log
- Verifies recieved events by printing

To be updated: Use HTTPS, auth tokens, structured storage, dashboard UI
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime
from pathlib import Path
from analyser import is_event_allowed
import uuid

# CONFIG
HOST = "0.0.0.0"
PORT = 8000
LOG_FILE = Path("events.log")
ALERTS_FILE = Path("alerts.log")

class CollectorHandler(BaseHTTPRequestHandler):
	"""
	Handles incoming HTTP requests that agents have POSTed
	"""

	def do_POST(self):
		"""
		Recieve JSON event and store it
		"""
		# 1) Read Request Body
		content_length = int(self.headers.get("Content-Length", "0"))
		raw_body = self.rfile.read(content_length)

		# 2) Parse JSON
		try:
			event = json.loads(raw_body.decode("utf-8"))
		except Exception as e:
			# 400 Bad Request
			self._respond_jjson(
				status=400,
				payload={"ok": False, "error": f"Invalid JSON: {e}"}
			)
			return

		# 3) Add Collector-Side Metadata
		event["recieved_at_utc"] = datetime.utcnow().isoformat() + "Z"
		event["collector_ip"] = self.server.server_address[0]

		# 5) Analyse Event and Print to Console
		event["result"], event["reason"] = is_event_allowed(event)
		print("-" * 50)
		print(f"Analysed Event: {event.get('event_type')}")
		print(json.dumps(event, indent=2))
		print(f"{event.get('result')}: {event.get('reason')}")
		print("-" * 50)

		# 6) Append event to logs as JSON entries
		try:
			with LOG_FILE.open("a", encoding="utf-8") as f:
				f.write(json.dumps(event) + "\n")
		except Exception as e:
			# 500 Write error
			self._respond_json(
				status=500,
				payload={"ok": False, "error": f"Failed to write log: {e}"}
			)
			return

		# 7) Append unauthorised events to logs as JSON entries
		if event.get('result') == "Unauthorised":
			try:
				alert = {
					"alert_id": str(uuid.uuid4()),
					"dismissed": False,
					**event
				}
				with ALERTS_FILE.open("a", encoding="utf-8") as f:
					f.write(json.dumps(alert) + "\n")
			except Exception as e:
				# 500 Write error
				self._respond_json(
					status=500,
					payload={"ok": False, "error": f"Failed to write log: {e}"}
				)
				return

		# 8) Success
		self._respond_json(status=200, payload={"ok": True})


	def _respond_json(self, status: int, payload: dict):
		"""
		Send JSON response in standardised format
		"""
		body = json.dumps(payload).encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(body)))
		self.end_headers()
		self.wfile.write(body)


def main():
	"""
	Start HTTP server and listen
	"""
	server = HTTPServer((HOST, PORT), CollectorHandler)
	print(f"Collector listening on http://{HOST}:{PORT}")
	print(f"Writing events to: {LOG_FILE.resolve()}")
	server.serve_forever()


if __name__ == "__main__":
	main()

