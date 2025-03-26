"""user CRUD operations"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.data.tables import TableServiceClient

from webapp.config import AZURE_STORAGE_CONNECTION_STRING

from ..config import USER_TABLE_NAME

# Initialize TableServiceClient
table_service_client = TableServiceClient.from_connection_string(
    AZURE_STORAGE_CONNECTION_STRING
)


def get_table_client(table_name):
    """Returns a table client for the specified table name."""
    return table_service_client.get_table_client(table_name)


def create_table_if_not_exists(obj, table_name):
    try:
        obj.create_table()
    except HttpResponseError:
        logging.warning(f"Table with name {table_name} already exists")


user_table = get_table_client(USER_TABLE_NAME)

# Initialize the User table (create if it doesn't exist)
create_table_if_not_exists(user_table, USER_TABLE_NAME)


async def create_user(
    display_name: str, user_name: str, mail: str, active: bool
) -> Dict[str, Any]:
    """
    Create a new user in the user table.
    """
    user_id = str(uuid.uuid4())
    user_entity = {
        "PartitionKey": "User",
        "RowKey": user_id,
        "displayName": display_name,
        "userName": user_name,
        "email": mail,
        "active": active,
        "created": datetime.now(timezone.utc).isoformat() + "Z",
        "lastModified": datetime.now(timezone.utc).isoformat() + "Z",
    }
    user_table.create_entity(user_entity)
    return user_entity


async def get_user(
    user_id: Optional[str] = None,
) -> Union[Dict[str, Any], List[Any], None]:
    """
    Retrieve a user by ID or return all users if no ID is provided.
    """
    if user_id:
        try:
            return user_table.get_entity("User", user_id)
        except ResourceNotFoundError:
            return None
        except Exception as e:
            return {"error": str(e)}
    return list(user_table.list_entities())


async def update_user(user_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update user details based on SCIM operations.
    """
    user = await get_user(user_id)
    if not user:
        return {}
    try:
        if "Operations" in updates:
            for operation in updates["Operations"]:
                op = operation.get("op")
                path = operation.get("path")
                value = operation.get("value")

                if not path or not isinstance(path, str):
                    raise ValueError("Each operation must have a valid 'path' string.")

                # Handle only "Add" and "Replace" operations (ignoring unsupported ops)
                if op.lower() == "add" or op.lower() == "replace":
                    user[path] = value

                elif op.lower() == "remove":
                    # For "Remove" operation, delete the key from the user entity
                    if path in user:
                        del user[path]
                    else:
                        logging.warning(
                            f"Property '{path}' does not exist. Skipping removal."
                        )

                else:
                    raise ValueError(f"Unsupported operation: {op}")
        else:
            raise ValueError("'Operations' field is missing in updates.")
        user["lastModified"] = datetime.now(timezone.utc).isoformat() + "Z"
        user_table.update_entity(user)
    except Exception as e:
        logging.error(f"Error updating user: {e}")
    return user


async def delete_user(user_id: str) -> None:
    """
    Delete a user by ID.
    """
    user_table.delete_entity("User", user_id)


async def list_users() -> List[Dict[str, Any]]:
    """
    List all users from the user table.
    """
    return list(user_table.list_entities())


async def get_user_by_username_or_email(user_name: str, email: str) -> Dict[str, Any]:
    """
    Retrieve a user by username or email.
    """
    for us in await list_users():
        if user_name == us["userName"] or email == us["email"]:
            return us
    return {}
