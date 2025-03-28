import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from email.message import EmailMessage
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.text import MIMEText


import datetime
import base64
import json

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://mail.google.com/"]

# Generate credentials either from saved token or through login flow
# If new credential generated, save to token.json
# https://developers.google.com/gmail/api/quickstart/python
def get_creds():
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    return creds



def decode_message(msg):
    if 'data' in msg:
        print("data only")
        return base64.urlsafe_b64decode(msg['data']).decode("utf-8")
    elif 'body' in msg and 'data' in msg['body']:
        return base64.urlsafe_b64decode(msg['body']['data']).decode("utf-8")
    return ""

def save_attachment(service, user_id, msg_id, attachment_id, filename, save_dir="attachments"):
    attachment = service.users().messages().attachments().get(userId=user_id, messageId=msg_id, id=attachment_id).execute()
    data = attachment.get("data", "")
    
    # Decode and save file
    file_data = base64.urlsafe_b64decode(data)
    os.makedirs(save_dir, exist_ok=True)
    file_path = os.path.join(save_dir, filename)

    with open(file_path, "wb") as f:
        f.write(file_data)
    
    print(f"Attachment saved: {file_path}")

# Get recent emails in last 30 minutes
def get_recent_emails(creds):
    service = build("gmail", "v1", credentials=creds)

    now = datetime.datetime.now(datetime.timezone.utc)
    one_hour_ago = now - datetime.timedelta(hours=1)
    query = f'after:{int(one_hour_ago.timestamp())}'
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    emails = []
    for msg in messages:
        msg_detail = service.users().messages().get(userId='me', id=msg['id']).execute()
        payload = msg_detail.get("payload", {})

        headers = payload.get("headers", [])
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), "No Subject")
        sender = next((header['value'] for header in headers if header['name'] == 'From'), "Unknown Sender")

        # Extract email body
        body = ""
        print("")
        print("")
        print("")
        print(subject)
        if "parts" in payload:
            for part in payload["parts"]:
                print(part["mimeType"])
                if part["mimeType"] == "text/plain":  # Get plain text email
                    body = decode_message(part["body"])
                    break
                elif part["mimeType"] == "text/html":  # Fallback to HTML if no plain text
                    body = decode_message(part["body"])
                elif part["mimeType"].startswith("application/") or part["mimeType"].startswith("image/"):  # Check for attachments
                    filename = part.get("filename")
                    attachment_id = part["body"].get("attachmentId")
                    if filename and attachment_id:
                        save_attachment(service, "me", msg['id'], attachment_id, filename)
        else:
            body = decode_message(payload.get("body", {}))

        emails.append({
            "id": msg['id'],
            "subject": subject,
            "from": sender,
            "body": body
        })
    TEMP_save_text(json.dumps(emails))
    # return emails



# files is dict {filename: file}
def send_message(cred, target, subject, text, files):
    try:
        service = build("gmail", "v1", credentials=cred)
        message = EmailMessage()
        message.set_content(text)
        message["To"] = target
        message["From"] = "me"
        message["Subject"] = subject

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()


        create_message = {
            "raw": encoded_message
        }
        send_message = (service.users().messages().send(userId="me", body=create_message).execute())

    except HttpError as error:
        print(f"An error occurred: {error}")
        send_message = None
    return send_message


        

def TEMP_save_text(text):
    with open("temp.txt", "w") as f:
        f.write(text)

if __name__ == "__main__":
    creds = get_creds()
    # get_recent_emails(creds)
    send_message(creds, "dylansburnerwhat@gmail.com", "test sent message", "test send message contents", {})