from __future__ import annotations
import urllib.parse
from typing import Optional, Dict, Any, List
import re
from urllib.parse import urlparse, urlunparse, parse_qs

import requests

from storage import get_spotify_app_token, read_db


def parse_spotify_id(url: str) -> tuple[str, str] | None:
    """
    Retourne (kind, id) pour des liens Spotify :
      - https://open.spotify.com/{track|album|playlist|artist|show|episode}/ID[?...]
      - https://open.spotify.com/intl-xx/{...}/ID
      - https://spotify.link/XXXXXXXX (shortlink → suivi de redirection)
      - https://spoti.fi/XXXXXXXX   (cas historiques)
      - URI spotify:{track|album|playlist|artist|show|episode}:ID

    kind ∈ {"track","album","playlist","artist","show","episode"}.
    """
    s = (url or "").strip()
    if not s:
        return None

    # 1) URI "spotify:kind:id"
    m = re.fullmatch(r"spotify:(track|album|playlist|artist|show|episode):([A-Za-z0-9]+)", s)
    if m:
        return m.group(1), m.group(2)

    # 2) Short-links à étendre si besoin
    try:
        netloc = urlparse(s).netloc.lower()
    except Exception:
        netloc = ""
    if netloc in {"spotify.link", "spoti.fi"}:
        expanded = _expand_url_follow_redirects(s)
        if expanded:
            s = expanded

    # 3) Normaliser l’URL (enlever query/fragment pour le parsing)
    try:
        u = urlparse(s)
        # on garde le path sans query/fragment
        s_no_q = urlunparse((u.scheme, u.netloc, u.path, "", "", ""))
    except Exception:
        s_no_q = s

    # 4) open.spotify.com (supporte le préfixe /intl-xx/)
    #    NB: on tolère des IDs plus longs (>=10) pour éviter de casser si Spotify change la longueur
    m = re.search(
        r"open\.spotify\.com/(?:intl-[^/]+/)?"
        r"(track|album|playlist|artist|show|episode)/([A-Za-z0-9]{10,})",
        s_no_q
    )
    if m:
        return m.group(1), m.group(2)

    # 5) Dernière chance : parfois les short-links redirigent avec query style ?si=... après l'ID.
    #    On réessaie sur l'URL complète (au cas où le path était OK mais noyé dans la query).
    m = re.search(
        r"open\.spotify\.com/(?:intl-[^/]+/)?"
        r"(track|album|playlist|artist|show|episode)/([A-Za-z0-9]{10,})",
        s
    )
    if m:
        return m.group(1), m.group(2)

    return None


def _expand_url_follow_redirects(url: str, timeout: float = 6.0) -> str | None:
    """
    Suit les redirections d’un short-link (spotify.link / spoti.fi).
    Essaie d’abord requests (HEAD puis GET), sinon retombe sur urllib.
    """
    # 1) via requests si dispo
    try:
        import requests  # type: ignore
        headers = {"User-Agent": "curl/7.88"}
        try:
            r = requests.head(url, allow_redirects=True, timeout=timeout, headers=headers)
            final = r.url
            # Parfois HEAD ne redirige pas correctement → GET
            if _looks_like_short(final):
                r = requests.get(url, allow_redirects=True, timeout=timeout, headers=headers)
                final = r.url
            if not _looks_like_short(final):
                return final
        except Exception:
            # on tombera sur urllib ci-dessous
            pass
    except Exception:
        pass

    # 2) fallback urllib
    try:
        import urllib.request
        class _NoRedirect(urllib.request.HTTPErrorProcessor):
            def http_response(self, request, response): return response
            https_response = http_response

        opener = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "curl/7.88"})
        resp = opener.open(req, timeout=timeout)
        # suivre manuellement la chaîne si Location
        final = url
        # On limite le nb de redirs manuelles
        for _ in range(10):
            loc = resp.headers.get("Location")
            if not loc:
                break
            # absolutiser
            final = urllib.parse.urljoin(final, loc)
            req = urllib.request.Request(final, method="HEAD", headers={"User-Agent": "curl/7.88"})
            resp = opener.open(req, timeout=timeout)
        return final
    except Exception:
        return None


def _looks_like_short(u: str) -> bool:
    try:
        nl = urlparse(u).netloc.lower()
        return nl in {"spotify.link", "spoti.fi"}
    except Exception:
        return False


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
