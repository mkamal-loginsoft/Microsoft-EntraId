import hashlib
import hmac
import logging
import secrets
from base64 import b64decode, b64encode

import msal
import requests
from azure.identity import ClientSecretCredential
from azure.mgmt.web import WebSiteManagementClient

from .access_token import AccessTokenManager
from ..config import (
    ADMIN_USERNAME,
    APP_NAME,
    CLIENT_ID,
    CLIENT_SECRET,
    FORCE_CHANGE_PASSWORD_ON_NEXT_SIGN_IN,
    GRAPH_API_ENDPOINT,
    RESOURCE_GROUP,
    SUBSCRIPTION_ID,
    TENANT_ID,
)

authority = f"https://login.microsoftonline.com/{TENANT_ID}"

token_manager = AccessTokenManager()

def validate_user_password(username, password):
    app = msal.PublicClientApplication(CLIENT_ID, authority=authority)

    try:
        print(
            f"Attempting to acquire a token using username: {username} and password: {password}... \n"
        )
        token_response = app.acquire_token_by_username_password(
            scopes=["https://graph.microsoft.com/.default"],
            username=username,
            password=password,
        )
        if "access_token" in token_response:
            print(
                f"Successfully acquired a token using username: {username} and password: {password}... \n"
            )
            return True
        else:
            print(
                f"Failed to acquire a token using username: {username} and password: {password}... \n"
            )
            return False
    except Exception as e:
        logging.error(f"Error validating user password: {e}")
        print(e)
        return False


def generate_email_body(users, to_user):
    if to_user:
        notify = (
            """</br><p>As your account was compromised, you will be <strong>forced to reset your password</strong> on your next login</p> </br>"""
            if FORCE_CHANGE_PASSWORD_ON_NEXT_SIGN_IN
            else ""
        )
        return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Security Alert: Compromised Account</title>
                <style>
                    body {{
                        font-family: 'Arial', sans-serif;
                        background-color: #f9f9f9;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        min-height: 100vh;
                    }}
                    .email-container {{
                        max-width: 600px;
                        width: 100%;
                        background-color: #ffffff;
                        padding: 30px;
                        border-radius: 12px;
                        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                        border: 1px solid #e0e0e0;
                    }}
                    .header {{
                        text-align: center;
                        font-size: 26px;
                        font-weight: bold;
                        color: #d32f2f;
                        margin-bottom: 20px;
                        padding-bottom: 10px;
                        border-bottom: 2px solid #e0e0e0;
                    }}
                    .content {{
                        font-size: 16px;
                        color: #444;
                        line-height: 1.8;
                    }}
                    .content strong {{
                        color: #d32f2f;
                    }}
                    .content p {{
                        margin: 15px 0;
                    }}
                    .details {{
                        background-color: #f8f8f8;
                        padding: 15px;
                        border-radius: 8px;
                        margin: 20px 0;
                        border: 1px solid #e0e0e0;
                    }}
                    .details p {{
                        margin: 10px 0;
                        font-size: 14px;
                        color: #555;
                    }}
                    .footer {{
                        margin-top: 25px;
                        font-size: 14px;
                        color: #777;
                        text-align: center;
                        border-top: 1px solid #e0e0e0;
                        padding-top: 15px;
                    }}
                    .footer p {{
                        margin: 5px 0;
                    }}
                    .footer a {{
                        color: #d32f2f;
                        text-decoration: none;
                        font-weight: bold;
                    }}
                    .footer a:hover {{
                        text-decoration: underline;
                    }}
                </style>
            </head>
            <body>
                <div class="email-container">
                    <div class="header">Security Alert: Compromised Account</div>
                    <div class="content">
                        <p>Hello <strong>{users.get("userName")}</strong>,</p>
                        <p>
                            Luminar Cognyte Threat Intelligence has detected that your account credentials have been compromised.
                            Below are the details of the leak:
                        </p>
                        <div class="details">
                            <p><strong>Leaked Password:</strong> {users.get("credential") if users.get("credential") else "N/A"}</p>
                            <p><strong>Leak Source:</strong> {users.get("source") if users.get("source") else "N/A"}</p>
                            <p><strong>Leak Source URL:</strong> {users.get("url", "Not available") if users.get("url") else "N/A"}</p>
                        </div>
                        {notify}
                    </div>
                    <div class="footer">
                        <p>Thank you,</p>
                        <p><strong>Luminar Cognyte Threat Intelligence Team</strong></p>
                    </div>
                </div>
            </body>
            </html>
            """

    notify = (
        """</br><p>As the accounts were compromised, the users will be <strong>forced to reset their password</strong> on their next login</p> </br>"""
        if FORCE_CHANGE_PASSWORD_ON_NEXT_SIGN_IN
        else ""
    )
    table_rows = ""
    for user in users:
        table_rows += f"""
            <tr>
                <td>{user.get("userName", "N/A")}</td>
                <td>{user.get("credential", "N/A") if user.get("credential") else "N/A"}</td>
                <td>{user.get("source", "N/A") if user.get("source") else "N/A"}</td>
                <td>{user.get("url", "N/A") if user.get("url") else "N/A"}</td>
            </tr>
            """

    return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Alert</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                }}
                .email-container {{
                    max-width: 1000px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    padding: 30px;
                }}
                .header {{
                    text-align: center;
                    font-size: 28px;
                    color: #d32f2f;
                    margin-bottom: 20px;
                }}
                .content {{
                    font-size: 16px;
                    color: #333;
                    line-height: 1.6;
                }}
                table {{
                    width: 95%;
                    max-width: 900px;
                    border-collapse: collapse;
                    table-layout: fixed;
                }}
                th, td {{
                    padding: 10px;
                    max-width: 200px; 
                    word-wrap: break-word;
                    white-space: normal;
                    padding: 12px;
                    text-align: left;
                }}
                table, th, td {{
                    border: 1px solid #ddd;
                }}
                th {{
                    background-color: #f8f8f8;
                    font-weight: bold;
                    color: #555;
                }}
                tr:nth-child(even) {{
                    background-color: #f9f9f9;
                }}
                tr:hover {{
                    background-color: #f1f1f1;
                }}
                .footer {{
                    margin-top: 30px;
                    font-size: 14px;
                    color: #666;
                    text-align: center;
                }}
                .footer p {{
                    margin: 5px 0;
                }}
                @media only screen and (max-width: 600px) {{
                    table, thead, tbody, th, td, tr {{
                        display: block;
                        width: 100%;
                    }}
                    th, td {{
                        max-width: 100%; /* Allow cells to take full width on small screens */
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">Security Alert: Compromised Accounts</div>
                <div class="content">
                    <p>Hello Admin,</p>
                    <p>
                        Cognyte Luminar Threat Intelligence has detected that the following accounts have been compromised.
                        Below are the details of the leaks:
                    </p>
                    <table>
                        <thead>
                            <tr>
                                <th>User Name</th>
                                <th>Password</th>
                                <th>Source</th>
                                <th>URL</th>
                            </tr>
                        </thead>
                        <tbody>
                            {table_rows}
                        </tbody>
                    </table>
                    {notify}
                    <p>
                        We strongly advise you to notify the affected users to reset their passwords immediately to secure their accounts.
                    </p>
                </div>
                <div class="footer">
                    <p>Thank you,</p>
                    <p>Threat Intelligence Team</p>
                </div>
            </div>
        </body>
        </html>
        """


# Function to prepare the email payload
def prepare_email_payload(email_body, to_email, cc_email=[]):
    email_payload = {
        "message": {
            "subject": "Alert From Cognyte Luminar Intelligence",
            "body": {"contentType": "html", "content": email_body},
            "toRecipients": [{"emailAddress": {"address": mail}} for mail in to_email],
        },
        "saveToSentItems": "true",
    }
    if cc_email:
        email_payload["message"]["ccRecipients"] = [
            {"emailAddress": {"address": mail}} for mail in cc_email
        ]
    return email_payload


# Function to send the email
def send_email(user_data, cc_email=[], to_user=True):
    access_token = token_manager.get_access_token()
    email_body = generate_email_body(user_data, to_user)

    if to_user:
        email_payload = prepare_email_payload(
            email_body, [user_data.get("email")], cc_email
        )
    else:
        email_payload = prepare_email_payload(email_body, cc_email)
    # Send mail request
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        f"{GRAPH_API_ENDPOINT}/users/{ADMIN_USERNAME}/sendMail",
        headers=headers,
        json=email_payload,
    )

    if response.status_code == 202:  # 202 means accepted/successful
        print(f"Email sent successfully.")
    else:
        logging.error(f"Failed to send email: {response.status_code}, {response.text}")


# Function to force a password reset on a user and user.ReadWrite.All is required(application permission if modifying other users if own then delegated permission is required.)
def force_password_reset(user_id):
    """Force a password reset for a user."""
    access_token = token_manager.get_access_token()

    url = f"{GRAPH_API_ENDPOINT}/users/{user_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True
        }
    }
    response = requests.patch(url, headers=headers, json=payload)
    if response.status_code == 204:
        logging.info(f"Successfully forced password reset for user: {user_id}")
        return True
    else:
        logging.error(f"Failed to force password reset for user {user_id}: {response.status_code} - {response.text}")
        return False

def revoke_sessions(user_id):
    """Revoke all signed-in sessions for a user."""
    access_token = token_manager.get_access_token()
    url = f"{GRAPH_API_ENDPOINT}/users/{user_id}/revokeSignInSessions"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers)
    if response.status_code == 200:
        logging.info(f"Successfully revoked sessions for user: {user_id}")
        return True
    else:
        logging.error(f"Failed to revoke sessions for user {user_id}: {response.status_code} - {response.text}")
        return False



def build_signature(
    customer_id: str,
    shared_key: str,
    date: str,
    content_length: str,
    method: str,
    content_type: str,
    resource: str,
):
    """
    Builds the signature for authenticating requests to Azure Log Analytics workspace.

    Args:
        customer_id (str): The customer ID or workspace ID for Azure Log Analytics workspace.
        shared_key (str): The shared key for authentication with Azure Log Analytics workspace.
        date (str): The date and time of the request in RFC1123 format.
        content_length (int): The length of the request body in bytes.
        method (str): The HTTP method of the request.
        content_type (str): The content type of the request.
        resource (str): The resource being accessed.

    Returns:
        str: The authorization header value for the request.
    """

    x_headers = "x-ms-date:" + date
    string_to_hash = (
        method
        + "\n"
        + content_length
        + "\n"
        + content_type
        + "\n"
        + x_headers
        + "\n"
        + resource
    )
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = b64decode(shared_key)
    encoded_hash = b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def save_to_log_workspace(
    log_analytics_uri: str,
    customer_id: str,
    shared_key: str,
    logs_obj: str,
    table_name: str,
):
    """
    Saves logs to Azure Log Analytics workspace using the specified log_analytics_uri, customer_id, shared_key, and logs_obj.

    Args:
        log_analytics_uri (str): The URI for the Azure Log Analytics workspace.
        customer_id (str): The customer ID or workspace ID for Azure Log Analytics workspace.
        shared_key (str): The shared key for authentication with Azure Log Analytics workspace.
        logs_obj (str): The logs to be sent to Azure Log Analytics workspace in JSON format.
        table_name (str): The table which will be created in Log analytics workspace for storing the logs.

    Returns:
        int: The HTTP response status code if successful, or if there was an error.
    """
    from email.utils import formatdate

    rfc1123date = formatdate(timeval=None, localtime=False, usegmt=True)
    signature = build_signature(
        customer_id,
        shared_key,
        rfc1123date,
        str(len(logs_obj)),
        "POST",
        "application/json",
        "/api/logs",
    )
    headers = {
        "content-type": "application/json",
        "Authorization": signature,
        "Log-Type": table_name,
        "x-ms-date": rfc1123date,
        "time-generated-field": "date",
    }
    try:
        print(logs_obj)
        response = requests.post(log_analytics_uri, data=logs_obj, headers=headers)
        print(
            f"Azure log analytics response code: {response.status_code}. and response text: {response.text} \n"
        )
    except Exception as ex:
        print("failed to connect to log analytics workspace. Error:" + " " + str(ex))
        logging.error(
            "failed to connect to log analytics workspace. Error:" + " " + str(ex)
        )
        logging.error(str(ex))
        logging.error("Invalid Workspace ID")
        return 500

    if response.status_code in range(200, 299):
        print("Events are processed into Azure.")
        return response.status_code
    else:
        print(response.content)
        print(
            "Events are not processed into Azure. Response code: {}".format(
                response.status_code
            )
        )
        return 500


def generate_and_set_secret_key():
    secret_key = secrets.token_hex(32)

    credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    web_client = WebSiteManagementClient(credential, SUBSCRIPTION_ID)
    app_settings = web_client.web_apps.list_application_settings(
        RESOURCE_GROUP, APP_NAME
    )

    app_settings.properties["SCIM_SERVER_SECRET_KEY"] = secret_key
    web_client.web_apps.update_application_settings(
        RESOURCE_GROUP, APP_NAME, app_settings
    )
    print("✅ Secret Key set successfully in Azure Web App!")
