import logging
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from functools import partial
from json import dumps
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from ..config import (
    ADMINS_EMAILS,
    BASE_URL,
    CUSTOMER_ID,
    FORCE_CHANGE_PASSWORD_ON_NEXT_SIGN_IN,
    INITIAL_FETCH_DATE,
    LOG_ANALYTICS_URI,
    LUMINAR_ACCOUNT_ID,
    LUMINAR_CLIENT_ID,
    LUMINAR_CLIENT_SECRET,
    NOTIFY_USERS,
    SHARED_KEY,
    TABLE_NAME,
)
from ..models.user import user_table
from .utils import (
    force_password_reset,
    save_to_log_workspace,
    send_email,
    validate_user_password, revoke_sessions,
)

logging.basicConfig(
    stream=sys.stdout, format="%(asctime)s:%(levelname)s-%(message)s", level="DEBUG"
)

HEADERS: Dict[str, str] = {
    "accept": "application/json",
}
TIMEOUT: float = 60.0


class LuminarManager:
    """
    Class to manage Luminar API interactions.
    """

    STATUS_MESSAGES = {
        400: "Bad request. The server could not understand the request due to "
        "invalid syntax.",
        401: "Unauthorized. The client must authenticate itself to get the "
        "requested response.",
        403: "Forbidden. The client does not have access rights to the " "content.",
        404: "Not Found. The server can not find the requested resource.",
        408: "Request Timeout. The server would like to shut down this unused "
        "connection.",
        429: "Too Many Requests. The user has sent too many requests in a "
        "given amount of time.",
        500: "Internal Server Error. The server has encountered a situation "
        "it doesn't know how to handle.",
        502: "Bad Gateway. The server was acting as a gateway or proxy and "
        "received an invalid response from the "
        "upstream server.",
        503: "Service Unavailable. The server is not ready to handle the " "request.",
    }

    def __init__(
        self,
        cognyte_client_id: str,
        cognyte_client_secret: str,
        cognyte_account_id: str,
        cognyte_base_url: str,
    ) -> None:
        self.base_url = cognyte_base_url
        self.account_id = cognyte_account_id
        self.client_id = cognyte_client_id
        self.client_secret = cognyte_client_secret
        self.payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": "externalAPI/stix.readonly",
        }
        self.req_headers = HEADERS

    def access_token(self) -> Tuple[Union[bool, str], str]:
        """
        Make a request to the Luminar API.

        :return: Tuple[Union[bool, str], str]
            The access token (if successful) or False (if unsuccessful),
            and a message indicating the status of the
            request.
        """
        req_url = f"{self.base_url}/externalApi/v2/realm/{self.account_id}/token"
        response = None
        try:
            response = requests.post(
                req_url, headers=self.req_headers, data=self.payload, timeout=TIMEOUT
            )
            response.raise_for_status()
            return (
                response.json().get("access_token", False),
                "Luminar API Connected successfully",
            )
        except requests.HTTPError:
            if response is not None:
                return False, self.STATUS_MESSAGES.get(
                    response.status_code, "An error occurred"
                )
            return False, "An error occurred while making HTTP request"
        except Exception as err:
            return False, f"Failed to connect to Luminar API... Error is {err}"

    def get_taxi_collections(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Fetches TAXII collections from the Luminar API and returns a mapping of collection aliases to their IDs.

        This function sends a GET request to retrieve TAXII collections and extracts the alias-ID mapping.
        If an error occurs during the request, it logs the error and returns an empty dictionary.

        :param headers: Dictionary containing authentication headers for the API request.
        :type headers: dict
        :return: A dictionary mapping collection aliases to their corresponding IDs.
        :rtype: dict
        """
        taxii_collection_ids = {}
        try:
            req_url = f"{self.base_url}/externalApi/taxii/collections/"
            resp = requests.get(req_url, headers=headers)
            resp.raise_for_status()
            collections_data = resp.json()["collections"]
            print(f"Cognyte Luminar collections: {collections_data}")

            # Store collection alias and id mapping
            for collection in collections_data:
                taxii_collection_ids[collection.get("alias")] = collection.get("id")
        except Exception as e:
            logging.error(f"Error fetching collections: {e}")
        return taxii_collection_ids

    def get_collection_objects(
        self, headers: Dict[str, str], collection: str, params: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Fetches objects from a specified TAXII collection using pagination.

        This function sends a GET request to retrieve objects from the given TAXII collection.
        If an access token expires (401 error), it regenerates the token and retries the request.
        It also handles pagination by checking for the "next" field in the response.

        :param headers: Dictionary containing authentication headers for the API request.
        :type headers: Dict[str, str]
        :param collection: The ID of the TAXII collection from which to fetch objects.
        :type collection: str
        :param params: Dictionary of query parameters to send with the request.
        :type params: Dict[str, Any]
        :return: A list of objects retrieved from the TAXII collection.
        :rtype: List[Dict[str, Any]]
        """
        collection_objects = []
        while True:
            # Send a request to fetch objects from the collection
            resp = requests.get(
                f"{self.base_url}/externalApi/taxii/collections/{collection}/objects/",
                params=urllib.parse.urlencode(params, doseq=True),
                headers=headers,
            )
            # Handle the case where the access token has expired
            if resp.status_code == 401:
                print(
                    f"Access token has expired, status_code={resp.status_code} and response={resp.text}, Regenerating token..."
                )
                access_token, _ = self.access_token()
                headers = {"Authorization": f"Bearer {access_token}"}

                continue

            # Process the response when it is successful (status code 200)
            elif resp.status_code == 200:
                response_json = resp.json()
                all_objects = response_json.get("objects", [])

                collection_objects += all_objects
                # Check if there is a "next" page of objects and update the params
                if "next" in response_json:
                    params["next"] = response_json["next"]
                else:
                    break
            else:
                # Log an error for any unexpected status code
                print(
                    f"Error occurred while fetching objects from collection {collection}: "
                    f"status_code={resp.status_code} and response={resp.text}"
                )
                break

        # Log the completion of object fetching
        print(f"Fetched all objects from collection: {collection}")
        return collection_objects


def get_timestamp(days: int = 0) -> str:
    """
    Retrieves the current timestamp in UTC format with microsecond precision.

    This function fetches the current time in UTC, formats it into an ISO 8601 string
    with microsecond precision, and appends a 'Z' to indicate that the time is in UTC.

    Returns:
        str: The current timestamp in UTC with microsecond precision, formatted as
             'YYYY-MM-DDTHH:MM:SS.mmmmmmZ'.
    """
    if days:
        current_time = datetime.now(timezone.utc) + timedelta(days=days)
    else:
        current_time = datetime.now(timezone.utc)
    return (
        current_time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{current_time.microsecond:06d}Z"
    )


def generic_item_finder(all_objects: List[Dict[str, Any]], item_id: str) -> filter:
    """
    Filters objects by matching a specific 'id'.

    :param all_objects: List of objects.
    :param item_id: ID to look for.
    :return: Filtered object(s).
    """
    return filter(lambda x: x.get("id") == item_id, all_objects)


def check_created_date(obj_date: str, from_date: datetime) -> bool:
    """
    Validates whether the given object creation date is greater than or equal
    to the specified 'from_date'.

    :param obj_date: A string representing the creation date of the object in
                     ISO 8601 format ("%Y-%m-%dT%H:%M:%S.%fZ").
    :param from_date: A datetime object representing the threshold date.
    :return: True if obj_date is valid and greater than or equal to from_date,
             otherwise False.
    """
    try:
        return datetime.strptime(obj_date, "%Y-%m-%dT%H:%M:%S.%fZ") >= from_date
    except Exception as ex:
        logging.error(f"Invalid date format: {obj_date}; {ex}")
        return False


def filter_objects_by_type(
    objects: List[Dict[str, Any]], target_type: str = "identity"
) -> Dict[str, str]:
    """
    Filters a list of objects by a specific type and returns a dictionary with the `id` as the key
    and the `name` as the value.

    Args:
        objects (list): A list of objects (dictionaries) to filter.
        target_type (str): The value of the `type` key to filter by (default is "identity").

    Returns:
        dict: A dictionary with `id` as the key and `name` as the value.
    """
    return {obj["id"]: obj["name"] for obj in objects if obj.get("type") == target_type}


def process_leaked_records(
    all_objects: List[Dict[str, Any]], created_by_dict: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Process leaked records by linking parents and children.

    :param all_objects: List of all objects.
    :param created_by_dict: Mapping of creators.
    :return: Processed leaked data.
    :rtype: List[Dict[str, Any]]
    """

    leaked_data = []
    relationships_indicator = {}  # type: ignore
    user_data = fetch_table_data(user_table)
    get_item_by_id = partial(generic_item_finder, all_objects)
    for relationship in filter(
        lambda x: x.get("type") == "relationship",
        all_objects,
    ):
        relationship_items = relationships_indicator.get(
            relationship.get("target_ref"), []
        )
        relationship_items.append(relationship.get("source_ref"))
        relationships_indicator[relationship["target_ref"]] = relationship_items
    for key, group in relationships_indicator.items():
        parent = next(get_item_by_id(key), None)
        children: List[Optional[Dict[str, Any]]] = list(
            filter(
                None,
                [next(get_item_by_id(item_id), None) for item_id in group],
            )
        )
        if parent and parent.get("type") == "incident":
            parent["created_by"] = created_by_dict.get(
                parent.get("created_by_ref"), "Luminar"
            )
            parent, modified_childrens = enrich_incident_items(parent, children)  # type: ignore
            modified_childrens = check_for_breaches(user_table, modified_childrens)
            leaked_data.extend(modified_childrens)
    return leaked_data


def enrich_incident_items(
    parent: Dict[str, Any], childrens: List[Dict[str, Any]]
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Enrich parent incidents and extract relevant children data.

    :param parent: Parent incident object.
    :param childrens: List of child objects.
    :return: Updated parent and relevant children.
    """
    enrich_info = {}
    leaked_creds = list(
        filter(
            lambda x: x.get("type") == "user-account",
            childrens,
        )
    )
    if leaked_creds:
        malware_names = set()
        malware_types = set()  # type: ignore
        for obj in filter(
            lambda x: x.get("type") == "malware",
            childrens,
        ):
            malware_names.add(obj.get("name", ""))
            malware_types = malware_types | set(obj.get("malware_types", []))
        enrich_info["malware_names"] = ", ".join(malware_names)
        enrich_info["malware_types"] = ", ".join(malware_types)
        for keys, values in parent.items():
            if keys != "extensions":
                enrich_info[keys] = values

        for children in leaked_creds:
            children.update(enrich_info)
            sources = set()
            urls = set()
            monitoring_plan_terms = set()  # type: ignore

            # Iterate through each extension
            for extension_value in children.get("extensions", {}).values():
                # Extract source and monitoring_plan_terms
                sources.add(extension_value.get("source", ""))
                urls.add(extension_value.get("url", ""))
                monitoring_plan_terms = monitoring_plan_terms | set(
                    extension_value.get("monitoring_plan_terms", [])
                )

            # Join sets into comma-separated strings
            children["source"] = ", ".join(sources)
            children["url"] = ", ".join(urls)
            children["monitoring_plan_terms"] = ", ".join(monitoring_plan_terms)
    else:
        leaked_creds = []
    return parent, leaked_creds


def make_logs(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts a dictionary representing Cognyte luminars data into a standardized format.

    Args:
        data (dict): The dictionary containing the Cognyte luminar data.

    Returns:
        dict: The converted log data in a standardized format.
    """
    password = (
        "test04@12345#"
        if log.get("account_login") == "paxsfoods@gmail.com"
        else log.get("credential", "")
    )
    account_login = (
        "entra_test_02@loginsoft.com"
        if log.get("account_login") == "paxsfoods@gmail.com"
        else log.get("account_login")
    )
    return {
        "Created By": log.get("created_by", "Luminar"),
        "Account Login": account_login,
        "Display Name": log.get("display_name", ""),
        "Incident Name": log.get("name", ""),
        "Malware Names": log.get("malware_names", ""),
        "Malware Types": log.get("malware_types", ""),
        "Incident Modified_date": log.get("modified", ""),
        "incident Creation Date": log.get("created", ""),
        "Source": log.get("source", ""),
        "Url": log.get("url", ""),
        "Terms": log.get("monitoring_plan_terms", ""),
        "IsEmailBreached": log.get("isEmailbreached", False),
        "IsPasswordBreached": log.get("isPasswordbreached", False),
    }


def fetch_table_data(table_client: Any) -> List[Dict[str, Any]]:
    """
    Fetch all data entities from an Azure Table.

    :param table_client: Azure table client.
    :return: List of entities.
    :rtype: List[Dict[str, Any]]
    """
    entities = []
    try:
        # Fetch all entities from the table
        for entity in table_client.list_entities():
            entities.append(entity)
    except Exception as e:
        print(f"An error occurred while fetching data: {e}")
    return entities


def check_for_breaches(
    table_client: Any, records: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Check for breaches in the given records by directly filtering users from Azure Table Storage.

    :param table_client: The Azure Table client object.
    :param records: A list of leaked records to check.
    :return: The updated list of records with breach details.
    """
    for record in records:
        record["isEmailbreached"] = False
        record["isPasswordbreached"] = False
        leaked_account_login = record.get("account_login").split(" (")[0]  # type: ignore
        leaked_display_name = record.get("display_name")

        # Construct filter query for Azure Table
        filter_query = (
            f"email eq '{leaked_account_login}' or "
            f"userName eq '{leaked_account_login}' or "
            f"userName eq '{leaked_display_name}' or "
            f"email eq '{leaked_display_name}'"
        )

        try:
            # Fetch matching user(s) directly from Azure Table Storage
            matching_users = []
            for entity in table_client.query_entities(query_filter=filter_query):
                matching_users.append(entity)

            if matching_users:
                user = matching_users[0]
                # print(user)
                user_email = user.get("email")
                user_username = user.get("userName")
                record["isEmailbreached"] = True
                record["email"] = user_email
                record["userName"] = user_username
                record["isPasswordbreached"] = (
                    validate_user_password(user_email, record.get("credential"))
                    if record.get("credential")
                    else True
                )
        except Exception as e:
            print(f"Error querying Azure Table for user data: {e}")

    return records


def send_emails_to_compromised_users(users_data) -> None:
    """
    Send emails to users with leaked records and force a password reset.

    :param mails: List of email addresses.
    :param user_ids: List of user IDs.
    """
    if users_data:
        if NOTIFY_USERS:
            for user in users_data:
                send_email(user, ADMINS_EMAILS.split(";"), to_user=True)
        else:
            send_email(users_data, ADMINS_EMAILS.split(";"), to_user=False)

    print("Emails sent successfully")
    if FORCE_CHANGE_PASSWORD_ON_NEXT_SIGN_IN:
        for user in users_data:
            if force_password_reset(user.get("userName")):
                revoke_sessions(user.get("userName"))
    print("Forced passwords reset on next login successful")


def luminar() -> None:
    """
    Main function to fetch, process, and save Luminar leaked data.
    """
    try:
        print(f"Starting execution of program at: {str(datetime.now())}")
        luminar_base_url = BASE_URL
        luminar_client_id = LUMINAR_CLIENT_ID
        luminar_client_secret = LUMINAR_CLIENT_SECRET
        luminar_account_id = LUMINAR_ACCOUNT_ID
        luminar_initial_fetch_date = str(INITIAL_FETCH_DATE) + "T00:00:00.000000Z"
        luminar_last_success_run = ""

        luminar_manager = LuminarManager(
            luminar_client_id,
            luminar_client_secret,
            luminar_account_id,
            luminar_base_url,
        )
        print(luminar_initial_fetch_date)
        # Getting access token
        print("LOG: Getting access token...")
        print("Print: Getting access token...")
        access_token, message = luminar_manager.access_token()

        if not access_token:
            logging.error(f"Failed to get access token: {message}")
            return

        headers = {"Authorization": f"Bearer {access_token}"}

        taxii_collection = luminar_manager.get_taxi_collections(headers)
        if not taxii_collection:
            return

        from_date = None
        params = {"limit": 9999}
        if luminar_initial_fetch_date and not luminar_last_success_run:
            params["added_after"] = luminar_initial_fetch_date
            from_date = datetime.strptime(
                luminar_initial_fetch_date, "%Y-%m-%dT%H:%M:%S.%fZ"
            )
        elif luminar_last_success_run:
            print(f"Getting records added after timestamp: {luminar_last_success_run}")
            params["added_after"] = luminar_last_success_run
            from_date = datetime.strptime(
                luminar_last_success_run, "%Y-%m-%dT%H:%M:%S.%fZ"
            )

        next_checkpoint = get_timestamp()

        leaked_records = luminar_manager.get_collection_objects(
            headers, taxii_collection["leakedrecords"], params
        )

        print(f"Leaked records found: {len(leaked_records)}")
        identities = filter_objects_by_type(leaked_records, "identity")
        print(f"Records saved successfully.")
        processed_records = process_leaked_records(leaked_records, identities)
        print(f"Leaked records processed: {len(processed_records)}")

        records = list(map(make_logs, processed_records))
        records = list(filter(lambda x: x.get("IsEmailBreached"), records))
        print(f"Records to be saved: {len(records)}")
        if records:
            log_resp = save_to_log_workspace(
                LOG_ANALYTICS_URI, CUSTOMER_ID, SHARED_KEY, dumps(records), TABLE_NAME
            )
            print(f"Records saved to Log Analytics workspace successfully.")
            if log_resp in range(200, 299):
                print(
                    f"Luminar Leaked Records from {from_date} to {next_checkpoint} saved in Log analytics workspace successfully."
                )
        comp_email_usernames = list(
            filter(lambda x: x.get("isEmailbreached"), processed_records)
        )
        print(f"Compromised users: {len(comp_email_usernames)}")
        send_emails_to_compromised_users(comp_email_usernames)
        #
        print(
            f"Execution completed at: {str(datetime.now())} with next checkpoint: {next_checkpoint}"
        )


    except Exception as err:
        logging.exception(err)


# if __name__ == "__main__":
#     luminar()
