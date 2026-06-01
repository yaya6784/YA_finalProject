__author__ = "Eilay Zafira"

import socket
import threading
import pygame

from tcp_by_size import send_with_size, recv_by_size
from crypto_utils import aes_encrypt_text, aes_decrypt_text, b64e, b64d, random_aes_key, rsa_encrypt_aes_key

# ---------- connection settings ----------
HOST = "127.0.0.1"
PORT = 5555

# ---------- screen settings ----------
SCREEN_W = 1000
SCREEN_H = 750
FPS = 60

# ---------- colors ----------
BG = (22, 22, 32)
GRID = (55, 55, 75)
WHITE = (240, 240, 240)
DARK = (35, 35, 50)
GRAY = (110, 110, 130)
GREEN = (60, 220, 120)
ORANGE = (255, 150, 40)
YELLOW = (255, 220, 120)
RED = (230, 70, 70)

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
    ERR01: "Invalid name",
    ERR02: "Bad protocol structure",
    ERR03: "First command must be LOGIN or SIGNP",
    ERR04: "Bad target values",
    ERR05: "Secure connection failed",
    ERR06: "Unknown command",
    ERR07: "Invalid password",
    ERR08: "Username already exists",
    ERR09: "Bad username or password",
    ERR10: "User already connected",
    ERR11: "Username does not exist"
}

# ---------- pygame setup ----------
pygame.init()
screen = pygame.display.set_mode((SCREEN_W, SCREEN_H))
pygame.display.set_caption("Blob Arena")
clock = pygame.time.Clock()
font = pygame.font.SysFont("arial", 30)
small_font = pygame.font.SysFont("arial", 20)

# ---------- connection data ----------
sock = None
aes_key = None
secure = False
connected = False

# ---------- client state ----------
my_id = None
name = ""
password = ""
active_field = 0    # 0 = username, 1 = password
msg = "Type username and password"
page = "login"      # login / signup / waiting / game / win
last_target = 0

# ---------- game state from server ----------
world_w = 1500
world_h = 1500
food_r = 8
phase = 0           # 0 waiting, 1 game, 2 winner
winner_id = 0
winner_name = ""
players = {}
foods = []
lock = threading.Lock()



def build_msg(cmd, *fields):
    return cmd + ("|" + "|".join(str(field) for field in fields) if fields else "")

def parse_msg(text):
    if text is None:
        return "", []
    parts = text.split("|")
    return parts[0], parts[1:]

def error_message(cmd, fields):
    if cmd in ERROR_TEXT:
        return cmd + " - " + ERROR_TEXT[cmd]
    if fields:
        return fields[0]
    return "Unknown error"

def draw_text(text, x, y, color=WHITE, use_small_font=False):
    chosen_font = small_font if use_small_font else font
    img = chosen_font.render(str(text), True, color)
    screen.blit(img, (x, y))

def clamp(value, min_value, max_value):
    return max(min_value, min(max_value, value))

def send_packet(text):
    if secure:
        text = aes_encrypt_text(text, aes_key)
    send_with_size(sock, text)

def read_packet():
    data = recv_by_size(sock)
    if not data:
        return None
    text = data.decode(errors="replace")
    if secure:
        try:
            return aes_decrypt_text(text, aes_key)
        except Exception:
            if text.startswith("ERR"):
                return text
            raise
    return text

def disconnect():
    global sock, connected, secure, aes_key
    connected = False
    secure = False
    aes_key = None
    try:
        if sock:
            sock.close()
    except Exception:
        pass
    sock = None

def connect_to_server(cmd, username, user_password):
    global sock, aes_key, secure, connected, my_id

    disconnect()
    sock = socket.socket()
    sock.connect((HOST, PORT))
    sock.settimeout(3)

    try:
        send_packet(build_msg(HELLO, "RSA"))
        cmd_from_server, fields = parse_msg(read_packet())
        if cmd_from_server.startswith("ERR"):
            raise RuntimeError(error_message(cmd_from_server, fields))
        if cmd_from_server != PUBKY or len(fields) != 1:
            raise RuntimeError("bad public key")

        aes_key = random_aes_key()
        encrypted_key = rsa_encrypt_aes_key(b64d(fields[0]), aes_key)
        send_packet(build_msg(AESKY, b64e(encrypted_key)))

        secure = True
        cmd_from_server, fields = parse_msg(read_packet())
        if cmd_from_server.startswith("ERR"):
            raise RuntimeError(error_message(cmd_from_server, fields))
        if cmd_from_server != OKAYS:
            raise RuntimeError("secure failed")

        send_packet(build_msg(cmd, username, user_password))
        cmd_from_server, fields = parse_msg(read_packet())
        if cmd_from_server.startswith("ERR"):
            raise RuntimeError(error_message(cmd_from_server, fields))
        if cmd_from_server != WELCM or len(fields) != 1:
            raise RuntimeError("login failed")

        my_id = int(fields[0])
        connected = True
        sock.settimeout(0.2)
        threading.Thread(target=receive_loop, daemon=True).start()

    except Exception:
        disconnect()
        raise

def receive_loop():
    global connected, phase, winner_id, winner_name, world_w, world_h, food_r, msg

    while connected:
        try:
            cmd, fields = parse_msg(read_packet())
        except socket.timeout:
            continue
        except Exception:
            connected = False
            msg = "Connection lost"
            break

        if cmd == STATE and len(fields) >= 8:
            update_state(fields)
        elif cmd.startswith("ERR"):
            msg = error_message(cmd, fields)

def update_state(fields):
    global phase, winner_id, winner_name, world_w, world_h, food_r

    with lock:
        phase = int(fields[0])
        winner_id = int(fields[1])
        winner_name = fields[2]
        world_w = int(fields[3])
        world_h = int(fields[4])
        food_r = int(fields[5])
        players.clear()
        foods.clear()

        for item in fields[6].split(";"):
            if item:
                data = item.split(",")
                players[int(data[0])] = {
                    "name": data[1],
                    "x": float(data[2]),
                    "y": float(data[3]),
                    "r": int(data[4]),
                    "ready": data[5] == "1",
                    "ingame": data[6] == "1",
                    "eaten": data[7] == "1",
                    "color": (int(data[8]), int(data[9]), int(data[10]))
                }

        for item in fields[7].split(";"):
            if item:
                x, y = item.split(",")
                foods.append((int(x), int(y)))

def get_camera(my_player):
    cam_x = clamp(int(my_player["x"] - SCREEN_W // 2), 0, world_w - SCREEN_W)
    cam_y = clamp(int(my_player["y"] - SCREEN_H // 2), 0, world_h - SCREEN_H)
    return cam_x, cam_y

def draw_blob(player, cam_x, cam_y):
    x = int(player["x"] - cam_x)
    y = int(player["y"] - cam_y)
    r = player["r"]
    pygame.draw.circle(screen, player["color"], (x, y), r)
    pygame.draw.circle(screen, YELLOW, (x, y), max(6, r // 2))
    img = small_font.render(player["name"], True, WHITE)
    screen.blit(img, (x - img.get_width() // 2, y - r - 22))

def draw_leaderboard(players_list):
    board = [player for player in players_list if player["ingame"]]
    board.sort(key=lambda player: player["r"], reverse=True)
    board = board[:6]
    box = pygame.Rect(SCREEN_W - 230, 15, 210, 45 + 25 * len(board))
    pygame.draw.rect(screen, DARK, box)
    pygame.draw.rect(screen, GRAY, box, 2)
    draw_text("Leaderboard", box.x + 15, box.y + 10, ORANGE, True)
    for i in range(len(board)):
        line = str(i + 1) + ". " + board[i]["name"] + " - " + str(board[i]["r"])
        draw_text(line, box.x + 15, box.y + 40 + i * 25, WHITE, True)

def draw_login_page():
    screen.fill(BG)
    draw_text("Blob Arena", 405, 80, ORANGE)
    draw_text(page.capitalize(), 440, 140)

    user_box = pygame.Rect(330, 230, 340, 50)
    pass_box = pygame.Rect(330, 310, 340, 50)
    pygame.draw.rect(screen, DARK, user_box)
    pygame.draw.rect(screen, DARK, pass_box)
    pygame.draw.rect(screen, ORANGE if active_field == 0 else GRAY, user_box, 3)
    pygame.draw.rect(screen, ORANGE if active_field == 1 else GRAY, pass_box, 3)

    draw_text("Username:", 205, 242, WHITE, True)
    draw_text("Password:", 205, 322, WHITE, True)
    draw_text(name, user_box.x + 15, user_box.y + 9)
    draw_text("*" * len(password), pass_box.x + 15, pass_box.y + 9)

    draw_text(msg, 330, 380, YELLOW, True)
    draw_text("ENTER - next/connect", 385, 430, WHITE, True)
    draw_text("UP/DOWN - switch field", 372, 465, WHITE, True)
    draw_text("TAB - switch login/signup", 360, 500, WHITE, True)

def draw_waiting_page(my_player, game_phase, win_name):
    screen.fill(BG)
    draw_text("Waiting Room", 400, 130, ORANGE)
    draw_text("Player: " + name, 390, 220)
    if my_player and my_player["eaten"]:
        draw_text("You were eaten!", 405, 270, RED)
        if game_phase == 1:
            draw_text("Press ENTER to return to the current game", 315, 320, GREEN, True)
        else:
            draw_text("Press ENTER when ready for a new game", 340, 320, GREEN, True)
        if game_phase == 2:
            draw_text(win_name + " won!", 425, 355, YELLOW, True)
    elif game_phase == 1:
        draw_text("Game is running", 400, 270, YELLOW)
        draw_text("Press ENTER to join this game", 370, 320, GREEN, True)
    elif game_phase == 2:
        draw_text(win_name + " won!", 425, 270, YELLOW)
        draw_text("Press ENTER when ready for a new game", 340, 320, GREEN, True)
    else:
        draw_text("Press ENTER when ready", 375, 305, GREEN, True)
        draw_text("New game starts when all players are ready", 320, 340, WHITE, True)

def draw_game_page(my_player, players_list, foods_list):
    global last_target
    cam_x, cam_y = get_camera(my_player)
    mouse_x, mouse_y = pygame.mouse.get_pos()
    now = pygame.time.get_ticks()
    if now - last_target > 70:
        send_packet(build_msg(TRGET, mouse_x + cam_x, mouse_y + cam_y))
        last_target = now

    screen.fill(BG)
    for x in range(-(cam_x % 40), SCREEN_W, 40):
        pygame.draw.line(screen, GRID, (x, 0), (x, SCREEN_H))
    for y in range(-(cam_y % 40), SCREEN_H, 40):
        pygame.draw.line(screen, GRID, (0, y), (SCREEN_W, y))
    for x, y in foods_list:
        pygame.draw.circle(screen, GREEN, (x - cam_x, y - cam_y), food_r)
    for player in players_list:
        if player["ingame"]:
            draw_blob(player, cam_x, cam_y)
    pygame.draw.circle(screen, RED, (mouse_x, mouse_y), 5)
    draw_leaderboard(players_list)

def draw_win_page():
    screen.fill(BG)
    draw_text("You Won!", 430, 230, ORANGE)
    draw_text("Press ENTER to start a new game", 340, 310, GREEN, True)

def update_page_by_state():
    global page
    with lock:
        my_player = players.get(my_id)
        game_phase = phase
        win_id = winner_id
    if page not in ("login", "signup"):
        if game_phase == 1 and my_player and my_player["ingame"]:
            page = "game"
        elif game_phase == 2 and win_id == my_id:
            page = "win"
        else:
            page = "waiting"

def handle_keydown(event):
    global name, password, active_field, page, msg
    if page in ("login", "signup"):
        if event.key == pygame.K_UP:
            active_field = 0
        elif event.key == pygame.K_DOWN:
            active_field = 1
        elif event.key == pygame.K_BACKSPACE:
            if active_field == 0:
                name = name[:-1]
            else:
                password = password[:-1]
        elif event.key == pygame.K_TAB:
            page = "signup" if page == "login" else "login"
            msg = "Type username and password"
        elif event.key == pygame.K_RETURN:
            if active_field == 0:
                if not name:
                    msg = "Username is required"
                else:
                    active_field = 1
            elif not name or not password:
                msg = "Username and password are required"
            else:
                try:
                    auth_cmd = LOGIN if page == "login" else SIGNP
                    connect_to_server(auth_cmd, name, password)
                    page = "waiting"
                    msg = "Connected" if auth_cmd == LOGIN else "Signup successful - logged in"
                except Exception as error:
                    msg = str(error)
        elif event.unicode.isprintable():
            if active_field == 0 and len(name) < 14:
                name += event.unicode
            elif active_field == 1 and len(password) < 30:
                password += event.unicode
    elif page in ("waiting", "win") and event.key == pygame.K_RETURN and connected:
        send_packet(build_msg(READY))
        page = "waiting"

def draw_current_page():
    if page in ("login", "signup"):
        draw_login_page()
    elif page == "waiting":
        with lock:
            my_player = players.get(my_id)
            game_phase = phase
            win_name = winner_name
        draw_waiting_page(my_player, game_phase, win_name)
    elif page == "win":
        draw_win_page()
    elif page == "game":
        with lock:
            my_player = players.get(my_id)
            players_list = list(players.values())
            foods_list = foods[:]
        if my_player and my_player["ingame"]:
            draw_game_page(my_player, players_list, foods_list)

def close_client():
    try:
        if connected:
            send_packet(build_msg(QUITT))
    except Exception:
        pass
    disconnect()

def main():
    running = True
    while running:
        update_page_by_state()
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                handle_keydown(event)
        draw_current_page()
        pygame.display.flip()
        clock.tick(FPS)
    close_client()
    pygame.quit()


main()
