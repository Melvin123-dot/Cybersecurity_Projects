import requests

# Firewall server URL
URL = "http://localhost:8080"

# Malicious request (Simulating Spring4Shell Exploit)
malicious_headers = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded"
}

malicious_payload = {
    "class.module.classLoader.resources.context.parent.pipeline.first.pattern": "malicious_code"
}

# Legitimate request (Safe traffic)
legitimate_headers = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}

legitimate_payload = {
    "username": "test_user",
    "password": "securepassword123"
}

def test_request(headers, data, test_type):
    response = requests.post(URL, headers=headers, data=data)
    print(f"Test: {test_type}")
    print(f"Response Code: {response.status_code}")
    print(f"Response Body: {response.text}\n")

if __name__ == "__main__":
    print("=== Running Firewall Test ===\n")

    # Test Malicious Request (Should be Blocked)
    test_request(malicious_headers, malicious_payload, "Malicious Request")

    # Test Legitimate Request (Should be Allowed)
    test_request(legitimate_headers, legitimate_payload, "Legitimate Request")
