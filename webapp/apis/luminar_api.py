import threading
from flask import Blueprint, jsonify, current_app

from .user_api import require_auth
from ..tasks.luminar import luminar
from ..tasks.utils import generate_and_set_secret_key

# Create a Blueprint
luminar_blueprint = Blueprint("luminar", __name__)  # pylint: disable=invalid-name


@luminar_blueprint.route("/trigger-luminar", methods=["POST"])
@require_auth
def trigger_luminar():
    """
    Route to trigger the luminar task asynchronously.

    The task will be run in a new thread to avoid blocking the API request.
    Returns a JSON response indicating success or failure.

    Returns:
        Response: JSON response with the operation status and message.
    """
    try:
        # Run luminar in a separate thread to avoid blocking
        threading.Thread(target=luminar, daemon=True).start()

        # Log task initiation
        current_app.logger.info("Luminar task triggered asynchronously.")

        # Return success response immediately
        return jsonify({
            "status": "success",
            "message": "Luminar task triggered successfully."
        }), 200
    except Exception as exc:  # Catch exceptions and log them
        current_app.logger.error("Error while triggering Luminar: %s", str(exc))
        return jsonify({
            "status": "error",
            "message": "Failed to trigger Luminar.",
            "error": str(exc)
        }), 500


@luminar_blueprint.route("/generate-secret-key", methods=["POST"])
@require_auth
def generate_secret_key():
    """
    Route to generate and set a secret key.

    Executes the generate_and_set_secret_key function and returns a JSON
    response indicating success or failure.

    Returns:
        Response: JSON response with the operation status and message.
    """
    try:
        # Call the generate_and_set_secret_key function
        generate_and_set_secret_key()

        # Log success
        current_app.logger.info("Secret key generated and set successfully.")

        # Return success response
        return jsonify({
            "status": "success",
            "message": "Secret key generated and set successfully."
        }), 200
    except Exception as exc:  # Catch exceptions and log them
        current_app.logger.error("Error while generating secret key: %s", str(exc))
        return jsonify({
            "status": "error",
            "message": "Failed to generate secret key.",
            "error": str(exc)
        }), 500
