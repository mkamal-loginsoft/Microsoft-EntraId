"""User API endpoints for Luminar Scim Server."""

import logging
import os
from functools import wraps
from typing import Any, Dict, Tuple, Union

from flask import Blueprint, Response, jsonify, request

from ..config import SCIM_BASE_URL
from ..models.user import (
    create_user,
    delete_user,
    get_user,
    get_user_by_username_or_email,
    list_users,
    update_user,
)

user_apis = Blueprint("user_apis", __name__)

secret = "000a841af621eee575a251289f2076973a650ebf21045f6c7e94fd3af8dbe2e3"
SECRET_KEY = os.environ.get("SCIM_SERVER_SECRET_KEY", secret)
logging.info("SCIM_SERVER_SECRET_KEY is %s", SECRET_KEY)
# pylint: disable=too-many-return-statements, broad-exception-caught


async def scim_user_response(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transforms a user dictionary into a SCIM-compliant response format.
    """
    return {
        "id": user["RowKey"],
        "userName": user["userName"],
        "displayName": user.get("displayName", ""),
        "emails": [{"value": user["email"], "primary": True, "type": "work"}],
        "active": user.get("active"),
        "created": user["created"],
        "lastModified": user["lastModified"],
        "meta": {
            "resourceType": "User",
            "created": user["created"],
            "lastModified": user["lastModified"],
            "location": f"{SCIM_BASE_URL}/Users/{user['RowKey']}",
        },
    }


def require_auth(func):
    """
    Decorator to enforce authentication using Bearer Token.
    """

    @wraps(func)
    async def wrapper(
        *args: Any, **kwargs: Any
    ) -> Union[Tuple[Response, int], Tuple[str, int]]:
        auth_key = request.headers.get("Authorization")
        if not auth_key or auth_key != f"Bearer {SECRET_KEY}":
            logging.error("Unauthorized access: Invalid SCIM_SERVER_SECRET_KEY")
            return jsonify({"error": "Unauthorized"}), 401
        return await func(*args, **kwargs)

    return wrapper


@user_apis.route("/Users", methods=["GET", "POST"])
@require_auth
async def get_user_api() -> Union[Tuple[Response, int], Tuple[str, int]]:  # noqa
    """
    Handles user retrieval and creation via SCIM API.
    """
    if request.method == "GET":
        filter_param = request.args.get("filter")
        users_list = [await scim_user_response(user) for user in await list_users()]

        if filter_param:
            try:
                field, operator, value = filter_param.split(" ", 2)
                if operator != "eq":
                    return jsonify({"detail": f"Unsupported operator: {operator}"}), 400
                value = value.strip('"')
                if field == "userName":
                    users_list = [
                        user for user in users_list if user["userName"] == value
                    ]
                else:
                    return jsonify({"detail": f"Unsupported field: {field}"}), 400
            except ValueError:
                return jsonify({"detail": "Invalid filter format"}), 400

        start_index = int(request.args.get("startIndex", 1)) - 1
        count = int(request.args.get("count", len(users_list)))
        users_list = users_list[start_index : start_index + count]

        user_response = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(users_list),
            "Resources": users_list,
        }
        response = jsonify(user_response)
        response.headers["Content-Type"] = "application/scim+json"
        return response, 200

    if request.method == "POST":
        data = request.json
        if not data or not data.get("userName") or not data.get("emails"):
            return (
                jsonify(
                    {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "status": "400",
                        "detail": "Missing required fields: userName and emails",
                    }
                ),
                400,
            )

        user_name = data["userName"]
        email = data["emails"][0].get("value")

        existing_user = await get_user_by_username_or_email(user_name, email)
        if existing_user:
            return (
                jsonify(
                    {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "status": "409",
                        "detail": "User already exists",
                    }
                ),
                409,
            )

        try:
            new_user = await create_user(
                data.get("displayName", ""), user_name, email, data.get("active")
            )
            user_response = await scim_user_response(new_user)
            user_response["schemas"] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
            response = jsonify(user_response)
            response.headers["Content-Type"] = "application/scim+json"
            return response, 201
        except Exception as e:
            logging.error("Error creating user: %s", str(e))
            return (
                jsonify(
                    {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "status": "500",
                        "detail": "Error creating user",
                    }
                ),
                500,
            )
    return "Unknow method", 400


@user_apis.route("/Users/<user_id>", methods=["GET", "PATCH", "DELETE", "PUT"])
@require_auth
async def user_operations_api(
    user_id: str,
) -> Union[Tuple[Response, int], Tuple[str, int]]:  # noqa
    """
    Handles user retrieval, update, and deletion by ID.
    """
    if request.method == "GET":
        user = await get_user(user_id)
        if user:
            response = jsonify(await scim_user_response(user))
            response.headers["Content-Type"] = "application/scim+json"
            return response, 200
        return "", 404

    if request.method in ["PATCH", "PUT"]:
        updates = request.json
        user = await update_user(user_id, updates)
        if not user:
            return (
                jsonify(
                    {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "status": "404",
                        "detail": "User not found",
                    }
                ),
                404,
            )
        user_response = await scim_user_response(user)
        user_response["schemas"] = ["urn:ietf:params:scim:schemas:core:2.0:User"]
        return jsonify(user_response), 200

    if request.method == "DELETE":
        user = await get_user(user_id)
        if not user:
            return (
                jsonify(
                    {
                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                        "status": "404",
                        "detail": "User not found",
                    }
                ),
                404,
            )
        await delete_user(user_id)
        return "", 204
    return "Unknow method", 400
