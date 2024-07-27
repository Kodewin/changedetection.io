import os

import jwt
import requests
from flask import jsonify, request
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, jwt_required

from . import auth_blueprint
from .models import User, db


def get_auth_tokens(code, redirect_uri):
    response = requests.post(
        "https://oauth2.googleapis.com/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        params={
            "code": code,
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    return response.json()


@auth_blueprint.route("/auth_url", methods=["GET"])
def auth_url():
    request_url = requests.Request(
        "GET",
        "https://accounts.google.com/o/oauth2/v2/auth",
        params={
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "redirect_uri": f"{os.environ['CLIENT_HOST']}/api/auth/callback/google",
            "scope": "https://www.googleapis.com/auth/userinfo.email "
            "https://www.googleapis.com/auth/userinfo.profile",
            "access_type": "offline",
            "response_type": "code",
            "prompt": "consent",
            "include_granted_scopes": "true",
        },
    )
    url = request_url.prepare().url
    return jsonify({"url": url})


@auth_blueprint.route("/google/login", methods=["POST"])
def google_login():
    code = request.get_json()["code"]
    token_data = get_auth_tokens(
        code, f"{os.environ['CLIENT_HOST']}/api/auth/callback/google"
    )
    data = jwt.decode(token_data["id_token"], options={"verify_signature": False})
    email = data["email"]
    name = data["name"]

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=name)
        db.session.add(user)
        db.session.commit()

    access_token = create_access_token(identity=email, fresh=True)
    refresh_token = create_refresh_token(identity=email)

    return jsonify({"access": access_token, "refresh": refresh_token}), 200


@auth_blueprint.route("/me", methods=["GET"])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()
    return jsonify(name=user.name, email=user.email), 200


@auth_blueprint.route("/token/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, fresh=False)
    refresh_token = create_refresh_token(identity=identity)
    return jsonify({"access": access_token, "refresh": refresh_token}), 200
