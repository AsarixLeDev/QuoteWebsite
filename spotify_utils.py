from __future__ import annotations

import re
import urllib.parse
from typing import Optional, Dict, Any, List

import requests

from storage import get_spotify_app_token, read_db


def parse_spotify_id(url: str) -> tuple[str, str] | None:
    """Retourne (kind, id) pour une URL open.spotify.com/{track|album|playlist}/ID."""
    m = re.search(r"open\.spotify\.com/(track|album|playlist)/([A-Za-z0-9]+)", url or "")
    if m:
        return m.group(1), m.group(2)
    return None


def fetch_track_meta(track_id: str) -> Optional[Dict[str, Any]]:
    """Retourne {title, artists, preview_url, image, external_url} via token 'app' (client credentials)."""
    db = read_db()
    token = get_spotify_app_token(db)
    if not token:
        return None
    r = requests.get(
        f"https://api.spotify.com/v1/tracks/{track_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    if r.status_code != 200:
        return None
    d = r.json()
    title = d.get("name")
    artists = [a.get("name") for a in d.get("artists", []) if a.get("name")]
    images = d.get("album", {}).get("images", [])
    img = images[0]["url"] if images else None
    ext = (d.get("external_urls") or {}).get("spotify")
    return {
        "title": title,
        "artists": artists,
        "preview_url": d.get("preview_url"),
        "image": img,
        "external_url": ext,
    }


def build_alt_links(title: str, artists: List[str]) -> Dict[str, Any]:
    """Construit des liens alternatifs (YouTube/SC) + essaie de résoudre un track Deezer."""
    q = f"{title} {' '.join(artists)}".strip()
    yt = "https://www.youtube.com/results?search_query=" + urllib.parse.quote(q)
    sc = "https://soundcloud.com/search?q=" + urllib.parse.quote(q)

    deezer_embed = None
    deezer_link = None
    try:
        dz_q = f'artist:"{artists[0]}" track:"{title}"' if artists else title
        dz_r = requests.get("https://api.deezer.com/search", params={"q": dz_q}, timeout=12)
        if dz_r.status_code == 200 and (dz := dz_r.json()).get("data"):
            track = dz["data"][0]
            tid = track.get("id")
            if tid:
                deezer_link = f"https://www.deezer.com/track/{tid}"
                deezer_embed = f"https://widget.deezer.com/widget/auto/track/{tid}?autoplay=false"
    except Exception:
        pass

    return {
        "youtube_search": yt,
        "soundcloud_search": sc,
        "deezer_link": deezer_link,
        "deezer_embed": deezer_embed,
    }
