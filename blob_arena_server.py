__author__ = "Eilay Zafira"

import os
import socket
import threading
import time
import random
import math
import secrets

from tcp_by_size import send_with_size, recv_by_size
from AsyncMessages import AsyncMessages
import user_db
from crypto_utils import aes_encrypt_text, aes_decrypt_text, b64e, b64d, ensure_rsa_keys, rsa_decrypt_aes_key

# ---------- settings ----------
HOST = "0.0.0.0"
PORT = 5555
WORLD_W = 1500
WORLD_H = 1500
FOOD_AMOUNT = 45
FOOD_R = 8
START_R = 28
FPS = 30
COLORS = [(255, 150, 40), (70, 150, 255), (180, 90, 255), (230, 70, 70), (60, 220, 120)]

# ---------- protocol commands ----------
HELLO = "HELLO"
PUBKY = "PUBKY"
AESKY = "AESKY"
OKAYS = "OKAYS"
LOGIN = "LOGIN"
SIGNP = "SIGNP"
READY = "READY"
TRGET = "TRGET"
QUITT = "QUITT"
WELCM = "WELCM"
STATE = "STATE"

# ---------- error commands ----------
ERR01 = "ERR01"
ERR02 = "ERR02"
ERR03 = "ERR03"
ERR04 = "ERR04"
ERR05 = "ERR05"
ERR06 = "ERR06"
ERR07 = "ERR07"
ERR08 = "ERR08"
ERR09 = "ERR09"
ERR10 = "ERR10"
ERR11 = "ERR11"

ERROR_TEXT = {
    ERR01: "illegal player name",
    ERR02: "bad protocol structure",
    ERR03: "first command must be LOGIN or SIGNP",
    ERR04: "bad target values",
    ERR05: "secure connection failed",
    ERR06: "unknown command",
    ERR07: "illegal password",
    ERR08: "username already exists",
    ERR09: "bad username or password",
    ERR10: "user already connected",
    ERR11: "username does not exist"
}

# ---------- rsa files ----------
BASE_DIR = os.path.dirname(__file__)
PRIVATE_FILE = os.path.join(BASE_DIR, "server_private.pem")
PUBLIC_FILE = os.path.join(BASE_DIR, "server_public.pem")
PEPPER_FILE = os.path.join(BASE_DIR, "pepper.txt")
private_pem, public_pem = ensure_rsa_keys(PRIVATE_FILE, PUBLIC_FILE)


def load_or_create_pepper():
    if os.path.exists(PEPPER_FILE):
        with open(PEPPER_FILE, "r", encoding="utf-8") as file:
            value = file.read().strip()
        if value:
            return value
    value = secrets.token_urlsafe(32)
    with open(PEPPER_FILE, "w", encoding="utf-8") as file:
        file.write(value)
    return value


user_db.init_db()
pepper = load_or_create_pepper()

# ---------- shared data ----------
async_msg = AsyncMessages()
lock = threading.Lock()
players = {}
clients = {}
sessions = {}
foods = []
phase = 0       # 0 = waiting room, 1 = game running, 2 = game ended with winner
winner_id = 0
winner_name = ""
logged_users = {}


def build_msg(cmd, *fields):
    if len(cmd) != 5:
        raise ValueError("command must be 5 chars")
    for field in fields:
        if "|" in str(field) or "\n" in str(field) or "\r" in str(field):
            raise ValueError("field breaks protocol")
    return cmd + ("|" + "|".join(str(field) for field in fields) if fields else "")

def parse_msg(text):
    if text is None or "\n" in text or "\r" in text:
        return None, []
    parts = text.split("|")
    if len(parts) == 0 or len(parts[0]) != 5:
        return None, []
    return parts[0], parts[1:]

def is_good_name(name):
    bad_chars = "|,;\n\r"
    if not name or len(name) > 14:
        return False
    for ch in bad_chars:
        if ch in name:
            return False
    return True

def is_good_password(password):
    if not password or len(password) > 30:
        return False
    return "|" not in password and "\n" not in password and "\r" not in password

def signup_user(username, password):
    if user_db.is_user_exist(username):
        return ERR08

    fake_email = username.lower() + "@blob.local"
    ok, code_or_error = user_db.signup_start(username, password, fake_email, pepper=pepper)
    if not ok:
        if code_or_error in ("USERNAME_TAKEN", "EMAIL_TAKEN"):
            return ERR08
        return ERR02

    ok, msg, verified_user = user_db.signup_verify(fake_email, code_or_error)
    if not ok:
        return ERR02

    if not user_db.is_password_ok(username, password, pepper=pepper):
        return ERR09
    return None

def login_user(username, password):
    if not user_db.is_user_exist(username):
        return ERR11
    if not user_db.is_password_ok(username, password, pepper=pepper):
        return ERR09
    return None

def clamp(value, min_value, max_value):
    return max(min_value, min(max_value, value))

def distance(x1, y1, x2, y2):
    return math.sqrt((x1 - x2) ** 2 + (y1 - y2) ** 2)

def new_food():
    return [random.randint(20, WORLD_W - 20), random.randint(20, WORLD_H - 20)]

def send_packet(sock, text):
    if sessions.get(sock, {}).get("secure"):
        text = aes_encrypt_text(text, sessions[sock]["aes"])
    send_with_size(sock, text)

def send_error(sock, code):
    send_packet(sock, build_msg(code, ERROR_TEXT.get(code, "error")))

def read_packet(sock):
    data = recv_by_size(sock)
    if not data:
        return None
    text = data.decode(errors="replace")
    if sessions.get(sock, {}).get("secure"):
        try:
            return aes_decrypt_text(text, sessions[sock]["aes"])
        except Exception:
            return "BADPK"
    return text

def handshake(sock):
    cmd, fields = parse_msg(read_packet(sock))
    if cmd != HELLO or fields != ["RSA"]:
        send_error(sock, ERR05)
        return False

    send_packet(sock, build_msg(PUBKY, b64e(public_pem)))

    cmd, fields = parse_msg(read_packet(sock))
    if cmd != AESKY or len(fields) != 1:
        send_error(sock, ERR05)
        return False

    try:
        aes_key = rsa_decrypt_aes_key(private_pem, b64d(fields[0]))
    except Exception:
        send_error(sock, ERR05)
        return False

    sessions[sock] = {"secure": True, "aes": aes_key}
    send_packet(sock, build_msg(OKAYS, "SECUR"))
    return True

def spawn_player(player):
    player["x"] = random.randint(100, WORLD_W - 100)
    player["y"] = random.randint(100, WORLD_H - 100)
    player["tx"] = player["x"]
    player["ty"] = player["y"]
    player["r"] = START_R

def make_player(player_id, name):
    player = {
        "id": player_id,
        "name": name,
        "ready": False,
        "ingame": False,
        "eaten": False,
        "color": COLORS[player_id % len(COLORS)]
    }
    spawn_player(player)
    return player

def start_game():
    global phase, winner_id, winner_name, foods
    phase = 1
    winner_id = 0
    winner_name = ""
    foods = [new_food() for _ in range(FOOD_AMOUNT)]
    for player in players.values():
        if player["ready"]:
            spawn_player(player)
            player["ready"] = False
            player["ingame"] = True
            player["eaten"] = False

def check_start():
    if phase != 0:
        return
    ready_players = [player for player in players.values() if player["ready"]]
    if len(ready_players) >= 2 and len(ready_players) == len(players):
        start_game()

def check_winner():
    global phase, winner_id, winner_name
    if phase != 1:
        return
    alive_players = [player for player in players.values() if player["ingame"]]
    if len(alive_players) == 1:
        winner = alive_players[0]
        phase = 2
        winner_id = winner["id"]
        winner_name = winner["name"]
        for player in players.values():
            player["ingame"] = False
            player["ready"] = False
            if player["id"] == winner_id:
                player["eaten"] = False
    elif len(alive_players) == 0:
        phase = 0
        winner_id = 0
        winner_name = ""

def encode_players():
    text = ""
    for player in players.values():
        color = player["color"]
        text += f'{player["id"]},{player["name"]},{int(player["x"])},{int(player["y"])},{int(player["r"])},'
        text += f'{int(player["ready"])},{int(player["ingame"])},{int(player["eaten"])},{color[0]},{color[1]},{color[2]};'
    return text

def queue_state():
    foods_text = "".join(f"{int(x)},{int(y)};" for x, y in foods)
    state_msg = build_msg(STATE, phase, winner_id, winner_name, WORLD_W, WORLD_H, FOOD_R, encode_players(), foods_text)
    for sock in list(clients.values()):
        async_msg.put_msg_in_async_msgs(state_msg, sock)

def update_movement():
    for player in players.values():
        if not player["ingame"]:
            continue
        dx = player["tx"] - player["x"]
        dy = player["ty"] - player["y"]
        d = math.sqrt(dx * dx + dy * dy)
        if d > 2:
            speed = max(2, 6 - player["r"] / 25)
            player["x"] += dx / d * speed
            player["y"] += dy / d * speed
        player["x"] = clamp(player["x"], player["r"], WORLD_W - player["r"])
        player["y"] = clamp(player["y"], player["r"], WORLD_H - player["r"])

def update_food():
    for player in players.values():
        if not player["ingame"]:
            continue
        for food in foods:
            if distance(player["x"], player["y"], food[0], food[1]) < player["r"] + FOOD_R:
                player["r"] += 1
                food[:] = new_food()

def update_player_hits():
    ids = list(players)
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            p1 = players[ids[i]]
            p2 = players[ids[j]]
            if not p1["ingame"] or not p2["ingame"]:
                continue
            if distance(p1["x"], p1["y"], p2["x"], p2["y"]) < max(p1["r"], p2["r"]):
                if p1["r"] > p2["r"] + 6:
                    eater, eaten = p1, p2
                elif p2["r"] > p1["r"] + 6:
                    eater, eaten = p2, p1
                else:
                    eater, eaten = None, None
                if eater is not None:
                    eater["r"] += max(3, eaten["r"] // 4)
                    eaten["ingame"] = False
                    eaten["ready"] = False
                    eaten["eaten"] = True
                    spawn_player(eaten)

def update_game():
    if phase != 1:
        return
    update_movement()
    update_food()
    update_player_hits()
    check_winner()

def game_loop():
    global foods
    foods = [new_food() for _ in range(FOOD_AMOUNT)]
    while True:
        with lock:
            update_game()
            queue_state()
        time.sleep(1 / FPS)

def parse_target(fields):
    if len(fields) != 2:
        return None
    try:
        return clamp(float(fields[0]), 0, WORLD_W), clamp(float(fields[1]), 0, WORLD_H)
    except Exception:
        return None

def process_client_msg(sock, player_id, text):
    global phase, winner_id, winner_name
    cmd, fields = parse_msg(text)
    if cmd is None:
        send_error(sock, ERR02)
        return True

    with lock:
        player = players.get(player_id)
        if player is None:
            return False

        if cmd == READY and len(fields) == 0:
            if phase == 1:
                spawn_player(player)
                player["ingame"] = True
                player["ready"] = False
                player["eaten"] = False
            else:
                if phase == 2:
                    phase = 0
                    winner_id = 0
                    winner_name = ""
                player["ready"] = True
                player["eaten"] = False
                check_start()

        elif cmd == TRGET:
            target = parse_target(fields)
            if target is None:
                send_error(sock, ERR04)
            elif phase == 1 and player["ingame"]:
                player["tx"], player["ty"] = target

        elif cmd == QUITT and len(fields) == 0:
            return False

        elif cmd in (READY, QUITT):
            send_error(sock, ERR02)

        else:
            send_error(sock, ERR06)

    return True

def cleanup_client(sock, player_id):
    with lock:
        player = players.get(player_id, {})
        was_ingame = player.get("ingame", False)
        username = player.get("name", "")
        clients.pop(player_id, None)
        players.pop(player_id, None)
        if username in logged_users and logged_users[username] == player_id:
            logged_users.pop(username, None)
        if was_ingame:
            check_winner()
    async_msg.delete_socket(sock)
    sessions.pop(sock, None)
    try:
        sock.close()
    except Exception:
        pass

def handle_client(sock, player_id, addr):
    try:
        if not handshake(sock):
            return

        cmd, fields = parse_msg(read_packet(sock))
        if cmd is None:
            send_error(sock, ERR02)
            return
        if cmd not in (LOGIN, SIGNP):
            send_error(sock, ERR03)
            return
        if len(fields) != 2:
            send_error(sock, ERR02)
            return

        username, password = fields[0], fields[1]
        if not is_good_name(username):
            send_error(sock, ERR01)
            return
        if not is_good_password(password):
            send_error(sock, ERR07)
            return

        if cmd == SIGNP:
            error_code = signup_user(username, password)
            if error_code is None:
                error_code = login_user(username, password)
        else:
            error_code = login_user(username, password)
        if error_code is not None:
            send_error(sock, error_code)
            return

        with lock:
            if username in logged_users:
                send_error(sock, ERR10)
                return
            clients[player_id] = sock
            players[player_id] = make_player(player_id, username)
            logged_users[username] = player_id

        send_packet(sock, build_msg(WELCM, player_id))

        while True:
            try:
                text = read_packet(sock)
                if text and not process_client_msg(sock, player_id, text):
                    break
            except socket.timeout:
                pass

            for msg in async_msg.get_async_messages_to_send(sock):
                send_packet(sock, msg)

    except Exception as error:
        print("client error:", error)
    finally:
        print("Disconnected", addr)
        cleanup_client(sock, player_id)

def main():
    server_sock = socket.socket()
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1000)
    print("Server listening on port", PORT)

    threading.Thread(target=game_loop, daemon=True).start()

    player_id = 1
    while True:
        client_sock, addr = server_sock.accept()
        print("Connection from", addr)
        client_sock.settimeout(0.05)
        async_msg.add_new_socket(client_sock)
        sessions[client_sock] = {"secure": False, "aes": None}
        threading.Thread(target=handle_client, args=(client_sock, player_id, addr), daemon=True).start()
        player_id += 1


if __name__ == "__main__":
    main()
