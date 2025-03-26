"""configurations for the app"""
import os

AZURE_STORAGE_CONNECTION_STRING = os.getenv(
    "AZURE_STORAGE_CONNECTION_STRING",""
)
USER_TABLE_NAME = "UserTable"
LEAKED_RECORD_TABLE_NAME = "LeakedRecordTable"


SCIM_BASE_URL = "/scim/v2"

BASE_URL = "https://demo.cyberluminar.com"

TENANT_ID = os.environ.get("TenantID", "")
CLIENT_ID: str = os.environ.get("ApplicationID", "")
CLIENT_SECRET: str = os.environ.get("ClientSecret", "")

LUMINAR_CLIENT_ID: str = os.environ.get("LuminarAPIClientID", "")
LUMINAR_CLIENT_SECRET: str = os.environ.get("LuminarAPIClientSecret", "")
LUMINAR_ACCOUNT_ID: str = os.environ.get("LuminarAPIAccountID", "")
CUSTOMER_ID = os.environ.get("WorkspaceID", "")
SHARED_KEY = os.environ.get("WorkspaceKey", "")


GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0"



LOG_ANALYTICS_URI = (
    f"https://{CUSTOMER_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
)
TABLE_NAME = os.environ.get("LogAnalyticsTableName", "CognyteLuminarLog_CL")
INITIAL_FETCH_DATE = os.environ.get("INITIAL_FETCH_DATE", "2025-02-20")

SUBSCRIPTION_ID = os.environ.get("SUBSCRIPTIONID", "")
RESOURCE_GROUP = os.environ.get("RESOURCEGROUP", "")

FORCE_CHANGE_PASSWORD_ON_NEXT_SIGN_IN = os.environ.get(
    "ForceChangePasswordOnNextSignIn", False
)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "integrations@loginsoft.com")
ADMINS_EMAILS = os.environ.get(
    "AdminsEmails", "mkamal@loginsoft.com;vrambatza@loginsoft.com"
)
NOTIFY_USERS = os.environ.get("NotifyUserViaEmail", False)


APP_NAME = os.environ.get("APP_NAME", "")
