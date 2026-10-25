import asyncio
import json
import os
import re
import secrets
import time
import urllib.parse
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = "https://mobilev2plus.holiday.com.tw"
LOGIN_PAGE = f"{BASE}/song/SongOrderLogin.aspx"
SONG_API = f"{BASE}/song/ah_song.ashx"
MORE_API = f"{BASE}/more/ah_more.ashx"
UA = "Mozilla/5.0 (Linux; Android 13)"

COOKIE_NAME = "ktv_session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 10  # 10 年，裝置上實質永久記住登入狀態
LOGIN_WINDOW = 15 * 60  # 15 分鐘
LOGIN_MAX_ATTEMPTS = 5  # 同一來源 15 分鐘內最多錯 5 次，避免被當成房號猜測工具
SEARCH_CACHE_TTL = 60  # 同關鍵字 60 秒內重搜直接吃快取，不再打上游

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")  # 放在 .env，沒設就等於關閉管理員登入
ADMIN_COOKIE_NAME = "ktv_admin"
ADMIN_COOKIE_MAX_AGE = 60 * 60 * 12  # 12 小時
MAX_ACTION_LOG = 300

DATA_DIR = Path("/app/data")
SESSIONS_FILE = DATA_DIR / "sessions.json"
BANNED_FILE = DATA_DIR / "banned_fps.json"
ACTIONS_FILE = DATA_DIR / "actions.json"

# session_token -> {"sid": ASP.NET SessionId, "room": 房號, "ts": 最後使用時間, "fp": 裝置指紋, "ip": IP}
sessions: dict[str, dict] = {}
# ip -> 失敗登入時間列表
login_attempts: dict[str, list[float]] = {}
admin_login_attempts: dict[str, list[float]] = {}
# (sid, word) -> (expires_at, items)
search_cache: dict[tuple[str, str], tuple[float, list[dict]]] = {}
# 被封鎖的裝置指紋
banned_fps: set[str] = set()
# 操作紀錄，最新的在最後面
action_log: list[dict] = []
# 目前有效的管理員 session token
admin_tokens: set[str] = set()

http_client: httpx.AsyncClient | None = None


def load_sessions() -> None:
    if SESSIONS_FILE.exists():
        try:
            sessions.update(json.loads(SESSIONS_FILE.read_text()))
        except Exception:
            pass  # 壞檔就當沒有舊資料，不要讓服務掛掉


def persist_sessions() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_FILE.write_text(json.dumps(sessions))


def load_banned() -> None:
    if BANNED_FILE.exists():
        try:
            banned_fps.update(json.loads(BANNED_FILE.read_text()))
        except Exception:
            pass


def persist_banned() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BANNED_FILE.write_text(json.dumps(sorted(banned_fps)))


def load_actions() -> None:
    if ACTIONS_FILE.exists():
        try:
            action_log.extend(json.loads(ACTIONS_FILE.read_text()))
        except Exception:
            pass


def persist_actions() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    del action_log[: max(0, len(action_log) - MAX_ACTION_LOG)]
    ACTIONS_FILE.write_text(json.dumps(action_log))


def log_action(sess: dict, action: str, detail: str = "") -> None:
    action_log.append({
        "ts": time.time(),
        "fp": sess.get("fp", ""),
        "ip": sess.get("ip", ""),
        "room": sess.get("room", ""),
        "action": action,
        "detail": detail,
    })
    persist_actions()


@asynccontextmanager
async def lifespan(_: FastAPI):
    global http_client
    load_sessions()  # 讀回上次部署前已登入的 session，重新部署不會洗掉使用者的登入狀態
    load_banned()
    load_actions()
    # 共用連線池：避免每次搜尋都重新 TLS handshake，明顯縮短回應時間
    http_client = httpx.AsyncClient(timeout=10)
    try:
        yield
    finally:
        await http_client.aclose()


app = FastAPI(lifespan=lifespan)


def too_many_attempts(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in login_attempts.get(ip, []) if now - t < LOGIN_WINDOW]
    login_attempts[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failure(ip: str) -> None:
    login_attempts.setdefault(ip, []).append(time.time())


def get_session(request: Request) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    sess = sessions.get(token) if token else None
    if not sess:
        raise HTTPException(401, "尚未登入包廂，請先輸入驗證碼")
    sess["ts"] = time.time()
    track_device(sess, request)
    return sess


def require_admin(request: Request) -> None:
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token or token not in admin_tokens:
        raise HTTPException(401, "需要管理員登入")


def describe_device(ua: str) -> str:
    """把 User-Agent 轉成人看得懂的裝置/瀏覽器描述，比純指紋雜湊好分辨多了。"""
    if not ua:
        return "未知裝置"
    device = "iPad" if "iPad" in ua else "iPhone" if "iPhone" in ua else \
        "Android" if "Android" in ua else "Mac" if "Macintosh" in ua else \
        "Windows" if "Windows" in ua else "裝置"
    if "Line/" in ua:
        browser = "LINE 內建瀏覽器"
    elif "CriOS" in ua:
        browser = "Chrome"
    elif "FxiOS" in ua:
        browser = "Firefox"
    elif "EdgiOS" in ua or "Edg/" in ua:
        browser = "Edge"
    elif "Chrome" in ua:
        browser = "Chrome"
    elif "Safari" in ua:
        browser = "Safari"
    elif "Firefox" in ua:
        browser = "Firefox"
    else:
        browser = ""
    m = re.search(r"CPU (?:iPhone )?OS (\d+)_(\d+)", ua) or re.search(r"Android (\d+(?:\.\d+)?)", ua)
    version = ""
    if m:
        version = ("iOS " + ".".join(m.groups())) if "iPhone" in ua or "iPad" in ua else ("Android " + m.group(1))
    parts = [p for p in [device, version, browser] if p]
    return " / ".join(parts) if parts else "未知裝置"


def track_device(sess: dict, request: Request) -> None:
    """記錄這個 session 目前用的裝置指紋跟 IP，方便事後分辨「同一個人連續做了哪些操作」。
    IP 目前拿到的可能是共用位址（同 Wi-Fi/有代理在前面），指紋才是真正能分辨不同手機的依據。"""
    fp = request.headers.get("x-device-fp", "")[:128]
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")[:300]
    screen = request.headers.get("x-device-screen", "")[:20]
    lang = request.headers.get("x-device-lang", "")[:20]
    conn = request.headers.get("x-device-conn", "")[:20]
    changed = (
        sess.get("fp") != fp or sess.get("ip") != ip or sess.get("ua") != ua
        or sess.get("screen") != screen or sess.get("lang") != lang or sess.get("conn") != conn
    )
    if not changed:
        return
    sess["fp"] = fp
    sess["ip"] = ip
    sess["ua"] = ua
    sess["device"] = describe_device(ua)
    sess["screen"] = screen
    sess["lang"] = lang
    sess["conn"] = conn
    persist_sessions()


def unquote(value):
    if isinstance(value, str):
        try:
            return urllib.parse.unquote(value)
        except Exception:
            return value
    return value


async def call_song_api(sid: str, payload: dict, url: str = SONG_API) -> dict:
    cookies = httpx.Cookies()
    cookies.set("ASP.NET_SessionId", sid, domain="mobilev2plus.holiday.com.tw")
    r = await http_client.post(
        url,
        content=json.dumps([payload]),
        cookies=cookies,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": UA,
            "Referer": f"{BASE}/song/songsearch.aspx",
        },
    )
    r.raise_for_status()
    if not r.text.strip():
        # MySong/KNow 對沒有包廂登入狀態的 session 回空內容（HTTP 200 但 body 長度 0）
        return {"Ok": "0", "Msg": "", "_no_room_session": True}
    data = r.json()
    result = data[0] if data else {"Ok": "0", "Msg": "沒有回應"}
    if result.get("Ok") in ("-90", "-102"):
        # SendAction/checkRoomOccupied 用這兩個代碼表示「請重新登入包廂」，跟上面的空 body 是同一種情況的另一種訊號
        result["_no_room_session"] = True
    return result


async def room_login(code: str) -> tuple[str | None, dict]:
    async with httpx.AsyncClient(timeout=10, headers={"User-Agent": UA}) as client:
        await client.get(
            LOGIN_PAGE,
            params={"regID": "web", "osID": "Android", "vendorID": "web"},
        )
        sid = client.cookies.get("ASP.NET_SessionId")
        if not sid:
            return None, {"Ok": "0", "Msg": "無法連線到好樂迪伺服器"}

        r = await client.post(
            SONG_API,
            content=json.dumps([{"m": "RoomLogin", "rid": code}]),
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Referer": LOGIN_PAGE,
            },
        )
        data = r.json()
        result = data[0] if data else {"Ok": "0", "Msg": "沒有回應"}
        return sid, result


async def call_with_relogin(sess: dict, payload: dict) -> dict:
    """給 MySong/KNow 這類需要房間登入狀態的呼叫用：上游 session 過期時自動用存著的房號重新登入一次再重試，
    使用者不會因為好樂迪那邊的 session 逾時而被退回驗證碼畫面。"""
    result = await call_song_api(sess["sid"], payload)
    if not result.get("_no_room_session"):
        return result

    new_sid, login_result = await room_login(sess["room"])
    if not new_sid or login_result.get("Ok") != "1":
        return {"Ok": "0", "Msg": "房間連線已逾時，請重新整理頁面"}

    sess["sid"] = new_sid
    persist_sessions()
    return await call_song_api(sess["sid"], payload)


def dedupe_items(items: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for item in items:
        sid = item.get("song_id")
        if sid in seen:
            continue
        seen.add(sid)
        out.append(item)
    return out


def parse_items(result: dict) -> list[dict]:
    if result.get("Ok") != "1":
        return []
    return [
        {
            "song_id": item.get("SongID"),
            "song_name": unquote(item.get("SongName")),
            "singer_name": unquote(item.get("SingerName")),
            "icon_url": unquote(item.get("iconurl")),
        }
        for item in (result.get("DataList") or [])
    ]


class LoginBody(BaseModel):
    code: str


class SearchBody(BaseModel):
    word: str
    kind: str | None = None  # 不帶代表同時搜歌名+歌手；也可手動指定 "1"=歌曲 / "0"=歌手


class SongListBody(BaseModel):
    type: str  # N=新進歌曲 T=新歌排行榜 O=點播排行榜
    lan: str  # 1國語 2台語 3粵語 4英語 5日語 7韓語 8越南


class OrderBody(BaseModel):
    song_id: str
    action: str  # order | quick | songbook


class RemoteBody(BaseModel):
    act: str


ACTION_MAP = {"order": "1", "quick": "2", "songbook": "3"}

REMOTE_ACTIONS = {
    "music_up", "music_down",
    "mic_up", "mic_down",
    "tone_up", "tone_down", "tone_std",
    "echo_up", "echo_down", "echo_std",
    "cut", "mute", "pause", "repeat", "vocal",
}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/session")
async def session_status(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    return {"logged_in": bool(token and token in sessions)}


@app.post("/api/login")
async def login(body: LoginBody, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    if too_many_attempts(ip):
        raise HTTPException(429, "嘗試次數過多，請稍後再試")

    fp = request.headers.get("x-device-fp", "")[:128]
    if fp and fp in banned_fps:
        raise HTTPException(403, "此裝置已被管理員封鎖")

    code = body.code.strip().upper()
    if len(code) != 4:
        raise HTTPException(400, "請輸入正確的4位包廂驗證碼")

    sid, result = await room_login(code)
    if not sid:
        raise HTTPException(502, result.get("Msg") or "無法連線到好樂迪伺服器")

    if result.get("Ok") != "1":
        record_failure(ip)
        raise HTTPException(401, result.get("Msg") or "驗證碼錯誤")

    token = secrets.token_urlsafe(32)
    sessions[token] = {"sid": sid, "room": code, "ts": time.time()}
    track_device(sessions[token], request)
    log_action(sessions[token], "login", code)
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
    )
    return {"ok": True, "msg": result.get("Msg")}


@app.post("/api/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_NAME)
    sess = sessions.get(token) if token else None
    if sess:
        try:
            await call_song_api(sess["sid"], {"m": "RoomLogout"}, url=MORE_API)
        except Exception:
            pass  # 上游登出失敗就算了，反正本機 session 一樣會清掉
        sessions.pop(token, None)
        persist_sessions()
    response.delete_cookie(COOKIE_NAME)
    return {"ok": True}


@app.get("/api/room-status")
async def room_status(request: Request):
    """對應官方每 2 分鐘的包廂使用中檢查：房間如果已經結束使用（退房/逾時），
    直接告訴前端把使用者導回驗證碼畫面，而不是讓後續操作一直卡在看不懂的錯誤訊息。"""
    sess = get_session(request)
    result = await call_with_relogin(sess, {"m": "checkRoomOccupied"})
    occupied = result.get("Ok") == "1"
    return {"occupied": occupied, "msg": unquote(result.get("Msg")) or ""}


@app.post("/api/search")
async def search(body: SearchBody, request: Request):
    sess = get_session(request)
    word = body.word.strip()
    if not word:
        return {"ok": False, "msg": "請輸入搜尋關鍵字"}

    cache_key = (sess["sid"], f"{body.kind or 'all'}:{word}")
    cached = search_cache.get(cache_key)
    if cached and cached[0] > time.time():
        return {"ok": True, "items": cached[1], "cached": True}

    encoded_word = urllib.parse.quote(word)
    kinds = [body.kind] if body.kind is not None else ["1", "0"]  # 預設同時搜歌名+歌手
    results = await asyncio.gather(
        *(
            call_song_api(sess["sid"], {"m": "SongSearch", "kind": k, "songwords": "", "word": encoded_word})
            for k in kinds
        )
    )
    items = dedupe_items([item for r in results for item in parse_items(r)])

    if not items:
        msg = next((unquote(r.get("Msg")) for r in results if r.get("Msg")), "查無資料")
        return {"ok": False, "msg": msg}

    search_cache[cache_key] = (time.time() + SEARCH_CACHE_TTL, items)
    return {"ok": True, "items": items}


@app.post("/api/songlist")
async def songlist(body: SongListBody, request: Request):
    sess = get_session(request)
    cache_key = (sess["sid"], f"list:{body.type}:{body.lan}")
    cached = search_cache.get(cache_key)
    if cached and cached[0] > time.time():
        return {"ok": True, "items": cached[1], "cached": True}

    result = await call_song_api(sess["sid"], {"m": "SongList", "type": body.type, "lan": body.lan})
    items = parse_items(result)
    if not items:
        return {"ok": False, "msg": unquote(result.get("Msg")) or "查無歌曲"}

    search_cache[cache_key] = (time.time() + SEARCH_CACHE_TTL, items)
    return {"ok": True, "items": items}


@app.post("/api/order")
async def order(body: OrderBody, request: Request):
    sess = get_session(request)
    t = ACTION_MAP.get(body.action)
    if not t:
        raise HTTPException(400, "未知的操作")
    result = await call_with_relogin(sess, {"m": "MySong", "id": body.song_id, "t": t})
    log_action(sess, f"order:{body.action}", body.song_id)
    return {"ok": result.get("Ok") == "1", "msg": unquote(result.get("Msg")) or ""}


@app.get("/api/now")
async def now_playing(request: Request):
    sess = get_session(request)
    result = await call_with_relogin(sess, {"m": "KNow"})
    return {"singer": unquote(result.get("Singer")) or ""}


@app.post("/api/remote")
async def remote(body: RemoteBody, request: Request):
    sess = get_session(request)
    if body.act not in REMOTE_ACTIONS:
        raise HTTPException(400, "未知的遙控器動作")
    result = await call_with_relogin(sess, {"m": "SendAction", "act": body.act})
    log_action(sess, "remote", body.act)
    return {"ok": result.get("Ok") == "1", "msg": unquote(result.get("Msg")) or ""}


class AdminLoginBody(BaseModel):
    password: str


class AdminBanBody(BaseModel):
    fp: str


@app.post("/api/admin/login")
async def admin_login(body: AdminLoginBody, request: Request, response: Response):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = [t for t in admin_login_attempts.get(ip, []) if now - t < LOGIN_WINDOW]
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(429, "嘗試次數過多，請稍後再試")

    if not ADMIN_PASSWORD or not secrets.compare_digest(body.password.encode(), ADMIN_PASSWORD.encode()):
        attempts.append(now)
        admin_login_attempts[ip] = attempts
        raise HTTPException(401, "密碼錯誤")

    token = secrets.token_urlsafe(32)
    admin_tokens.add(token)
    response.set_cookie(
        ADMIN_COOKIE_NAME, token,
        httponly=True, secure=True, samesite="lax", max_age=ADMIN_COOKIE_MAX_AGE,
    )
    return {"ok": True}


@app.post("/api/admin/logout")
async def admin_logout(request: Request, response: Response):
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if token:
        admin_tokens.discard(token)
    response.delete_cookie(ADMIN_COOKIE_NAME)
    return {"ok": True}


@app.get("/api/admin/sessions")
async def admin_sessions(request: Request):
    require_admin(request)
    out = [
        {
            "room": sess.get("room", ""),
            "fp": sess.get("fp", ""),
            "ip": sess.get("ip", ""),
            "ts": sess.get("ts", 0),
            "device": sess.get("device", "未知裝置"),
            "screen": sess.get("screen", ""),
            "lang": sess.get("lang", ""),
            "conn": sess.get("conn", ""),
            "banned": sess.get("fp") in banned_fps if sess.get("fp") else False,
        }
        for sess in sessions.values()
    ]
    out.sort(key=lambda s: s["ts"], reverse=True)
    return {"sessions": out, "banned_fps": sorted(banned_fps)}


@app.get("/api/admin/actions")
async def admin_actions(request: Request):
    require_admin(request)
    return {"actions": list(reversed(action_log[-200:]))}


@app.post("/api/admin/ban")
async def admin_ban(body: AdminBanBody, request: Request):
    require_admin(request)
    if not body.fp:
        raise HTTPException(400, "缺少裝置指紋")
    banned_fps.add(body.fp)
    persist_banned()
    to_remove = [t for t, s in sessions.items() if s.get("fp") == body.fp]
    for t in to_remove:
        sessions.pop(t, None)
    if to_remove:
        persist_sessions()
    return {"ok": True, "kicked": len(to_remove)}


@app.post("/api/admin/unban")
async def admin_unban(body: AdminBanBody, request: Request):
    require_admin(request)
    banned_fps.discard(body.fp)
    persist_banned()
    return {"ok": True}


static_dir = Path(__file__).parent / "static"
app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
