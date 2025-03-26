import logging
import threading
import time
from typing import Optional

import msal
import requests

from webapp.config import GRAPH_API_ENDPOINT, CLIENT_ID, CLIENT_SECRET


class AccessTokenManager:
    """
    A Singleton class to manage Microsoft Defender access tokens. This ensures that
    the token is only generated once and is refreshed automatically every hour,
    or if it is revoked externally.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        # Singleton logic
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls, *args, **kwargs)
                    cls._instance._token = None
                    cls._instance._last_fetched_time = None
                    cls._instance._expiration_time = 3598  # Default expiration: 1 hour
        return cls._instance

    def __init__(self):
        pass

    def _fetch_new_token(self) -> Optional[str]:
        """
        Fetches a new access token from the token endpoint.

        Returns:
            Optional[str]: The new access token, or None if the request fails.
        """
        logging.info("Fetching a new access token...")
        app = msal.ConfidentialClientApplication(
            CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET
        )
        # Get token for Microsoft Graph
        token_response = app.acquire_token_for_client(scopes=[default_scope])
        if "access_token" in token_response:
            return token_response["access_token"]
        else:
            raise Exception(f"Could not acquire token: {token_response}")


    def _is_token_valid(self, token: str) -> bool:
        """
        Mock function to check if the token is still valid.

        Replace this with actual logic to validate the token.
        For example, make a test API call using the token or validate via an endpoint.

        Args:
            token (str): The token to validate.

        Returns:
            bool: True if the token is valid, False otherwise.
        """
        logging.info("Validating access token...")

        # Replace with an actual validation mechanism (e.g., pinging an endpoint)
        try:
            response = requests.get(
                GRAPH_API_ENDPOINT + "/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,  # Example timeout for validation
            )
            return response.status_code == 200
        except requests.RequestException as e:
            logging.error(f"Token validation failed: {e}")
            return False

    def get_access_token(self) -> Optional[str]:
        """
        Retrieves a valid access token. If the token is older than its expiration time,
        revoked externally, or invalid, it will fetch a new token.

        Returns:
            Optional[str]: A valid access token, or None if unable to fetch the token.
        """
        current_time = time.time()

        # Check if the token is missing or expired
        if (
            not self._token
            or (current_time - self._last_fetched_time) > self._expiration_time
        ):
            with self._lock:
                if (
                    not self._token
                    or (current_time - self._last_fetched_time) > self._expiration_time
                ):
                    self._token = self._fetch_new_token()
                    self._last_fetched_time = time.time() if self._token else None
                    logging.info("Access token updated.")

        # Validate the token before returning it
        if self._token and not self._is_token_valid(self._token):
            with self._lock:
                self._token = self._fetch_new_token()
                self._last_fetched_time = time.time() if self._token else None
                logging.info("Access token refreshed due to validation failure.")

        return self._token


token_manager = AccessTokenManager()