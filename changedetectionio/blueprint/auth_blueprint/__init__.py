from flask import Blueprint

auth_blueprint = Blueprint("auth_blueprint", __name__)

from . import views, models


def init_db(app):
    models.db.init_app(app)
