import logging

from flask import Flask

from webapp.apis.luminar_api import luminar_blueprint
from webapp.tasks.utils import generate_and_set_secret_key

from webapp.apis.user_api import user_apis

LOGGING_LEVEL = logging.DEBUG
LOGGING_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

logging.basicConfig(
    level=LOGGING_LEVEL,
    format=LOGGING_FORMAT,
    handlers=[logging.FileHandler("scim_app.log"), logging.StreamHandler()],
)


generate_and_set_secret_key()


def create_app():
    app = Flask(__name__)
    app.logger.setLevel(LOGGING_LEVEL)
    app.register_blueprint(user_apis, url_prefix="/scim/v2")
    app.register_blueprint(luminar_blueprint, url_prefix="/luminar")
    return app


app = create_app()
