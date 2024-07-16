# 📧 Roblox Email Verification Script 📧

This script automates the process of verifying emails for Roblox accounts. It utilizes a temporary email service to receive verification emails and extracts the verification ticket to complete the process.

## 🌟 Features 🌟
- 📨 Generate a temporary email
- 📤 Send a verification request to Roblox
- 📬 Fetch the verification email
- 🔍 Extract the verification ticket
- ✅ Verify the email using the ticket

## 🛠️ Setup 🛠️
1. 📥 **Install Dependencies:**
    Make sure you have `requests`, `rich`, and `re` libraries installed. You can install them using pip:
    ```sh
    pip install requests rich
    ```

2. 📄 **Create a `cookies.txt` File:**
    In the same directory as your script, create a `cookies.txt` file containing Roblox security cookies. Each line should have one cookie in the format:
    ```plaintext
    YOUR_ROBLOSECURITY_COOKIE_1
    YOUR_ROBLOSECURITY_COOKIE_2
    ```

3. 📝 **Run the Script:**
    Execute the script to start the email verification process.

## 📝 Script Overview 📝

```python
import requests
from rich.console import Console
import json
import time
import re

# Initialize console for colored printing
console = Console(highlight=False)

# Function to print with color
def cprint(color: str, content: str) -> None:
    console.print(f"[ [bold {color}]>[/] ] {content}")

# Function to get CSRF token
def get_csrf_token(session, cookie):
    url = 'https://catalog.roblox.com/'
    response = session.post(url, cookies=cookie)
    x = response.headers.get('x-csrf-token')
    cprint("green", "Successfully Got x-csrf-token: " + x)
    return x

# Function to send verification email
def verifyemail(session, csrf_token, email, cookie):
    url = "https://accountsettings.roblox.com/v1/email"
    payload = {
        "emailAddress": email,
        "password": ""  # No password needed if unverified
    }
    headers = {
        "content-type": "application/json;charset=UTF-8",
        "x-csrf-token": csrf_token,
    }
    response = session.post(url, json=payload, headers=headers, cookies=cookie)
    v = response.json()
    cprint("green", "Successfully Sent Verification Email! | Response: " + json.dumps(v))
    
    if "errors" in v:
        cprint("red", "Error occurred | response: " + json.dumps(v))
    else:
        cprint("green", "Email Sent Successfully | response: " + json.dumps(v))
    
    return v

# Function to get a temporary email
def get_temp_email():
    response = requests.get('https://www.1secmail.com/api/v1/?action=genRandomMailbox&count=1')
    email = response.json()[0]
    cprint("green", "Temporary email generated: " + email)
    return email

# Function to get verification email
def get_verification_email(temp_email):
    login, domain = temp_email.split('@')
    url = f'https://www.1secmail.com/api/v1/?action=getMessages&login={login}&domain={domain}'
    
    while True:
        response = requests.get(url)
        emails = response.json()
        if emails:
            email_id = emails[0]['id']
            email_url = f'https://www.1secmail.com/api/v1/?action=readMessage&login={login}&domain={domain}&id={email_id}'
            email_response = requests.get(email_url)
            email_content = email_response.json()
            cprint("green", "Verification email received: " + email_content['textBody'])
            return email_content['textBody']
        else:
            cprint("yellow", "Waiting for verification email...")
            time.sleep(10)

# Function to extract the verification ticket
def extract_ticket(email_body):
    match = re.search(r'ticket=([A-Za-z0-9%]+)', email_body)
    if match:
        ticket = match.group(1)
        cprint("green", "Ticket extracted: " + ticket)
        return ticket
    else:
        cprint("red", "Ticket not found in email body")
        return None

# Function to verify the ticket
def verify_ticket(session, csrf_token, ticket, cookie):
    url = "https://accountinformation.roblox.com/v1/email/verify"
    payload = {
        "ticket": ticket
    }
    headers = {
        "content-type": "application/json;charset=UTF-8",
        "x-csrf-token": csrf_token,
    }
    response = session.post(url, json=payload, headers=headers, cookies=cookie)
    v = response.json()
    cprint("green", "Email verification status: " + json.dumps(v))
    return v

# Function to read cookies from a file
def read_cookies_from_file(file_path):
    cookies = []
    with open(file_path, 'r') as file:
        for line in file:
            cookie = line.strip()
            cookies.append({'.ROBLOSECURITY': cookie})
    return cookies

# Main process
cookies_list = read_cookies_from_file('cookies.txt')

for cookie in cookies_list:
    session = requests.Session()
    try:
        csrf_token = get_csrf_token(session, cookie)
        temp_email = get_temp_email()
        send_request = verifyemail(session, csrf_token, temp_email, cookie)
        email_body = get_verification_email(temp_email)
        ticket = extract_ticket(email_body)
        if ticket:
            verify_ticket(session, csrf_token, ticket, cookie)
    except Exception as e:
        cprint("red", f"An error occurred: {e}")```
