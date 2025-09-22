from __future__ import annotations

import base64
import secrets
import urllib.parse

import requests
from flask import Blueprint, redirect, request, session, url_for, flash, jsonify
from flask_login import login_required, current_user

from storage import (
    read_db, write_db, get_spotify_conf,
    set_spotify_token_record, refresh_spotify_token, get_spotify_token_record
)

spotify_bp = Blueprint("spotify", __name__)

# Scopes requis pour le Web Playback SDK
SCOPES = "streaming user-read-email user-read-private user-modify-playback-state user-read-playback-state"


def _sp_conf():
    conf = get_spotify_conf(read_db())
    return conf.get("client_id"), conf.get("client_secret"), conf.get("redirect_uri")


@spotify_bp.route("/spotify/connect")
@login_required
def connect():
    client_id, _client_secret, redirect_uri = _sp_conf()
    if not (client_id and redirect_uri):
        flash("Spotify n'est pas configuré (client_id / redirect_uri).")
        return redirect(url_for("core.dashboard"))
    state = secrets.token_urlsafe(16)
    session["spotify_oauth_state"] = state
    q = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "state": state,
        "show_dialog": "true",
    }
    url = "https://accounts.spotify.com/authorize?" + urllib.parse.urlencode(q)
    return redirect(url)


@spotify_bp.route("/spotify/callback")
@login_required
def callback():
    client_id, client_secret, redirect_uri = _sp_conf()
    if request.args.get("state") != session.get("spotify_oauth_state"):
        flash("État OAuth invalide.")
        return redirect(url_for("core.dashboard"))
    code = request.args.get("code")
    if not code:
        flash("Aucun code OAuth reçu.")
        return redirect(url_for("core.dashboard"))

    auth = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    resp = requests.post(
        "https://accounts.spotify.com/api/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri},
        headers={"Authorization": f"Basic {auth}"},
        timeout=15,
    )
    if resp.status_code != 200:
        flash("Échec de l'authentification Spotify.")
        return redirect(url_for("core.dashboard"))

    data = resp.json()
    db = read_db()
    set_spotify_token_record(
        db, current_user.get_id(),
        data["access_token"], data.get("refresh_token", ""),
        data.get("expires_in", 3600)
    )
    write_db(db)
    flash("Spotify connecté !")
    return redirect(url_for("core.dashboard"))


@spotify_bp.route("/spotify/token")
@login_required
def token():
    db = read_db()
    rec = refresh_spotify_token(db, current_user.get_id())
    if rec is None:
        rec = get_spotify_token_record(db, current_user.get_id())
    if not rec:
        return jsonify({"error": "not_connected"}), 401
    write_db(db)  # si refresh effectué
    return jsonify({"access_token": rec["access_token"]})


@spotify_bp.route("/spotify/status")
@login_required
def status():
    db = read_db()
    rec = get_spotify_token_record(db, current_user.get_id())
    return jsonify({"connected": bool(rec)})


@spotify_bp.route("/spotify/disconnect")
@login_required
def disconnect():
    db = read_db()
    store = db.setdefault("oauth", {}).setdefault("spotify_tokens", {})
    store.pop(current_user.get_id().strip().lower(), None)
    write_db(db)
    flash("Spotify déconnecté.")
    return redirect(url_for("core.dashboard"))
