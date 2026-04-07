import requests

res = requests.post("http://127.0.0.1:5000/analyze", json={
    "url": "http://secure-login-paypal.com"
})

print(res.json())