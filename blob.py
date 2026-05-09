import pygame
import math

# ---------------- CONFIG ----------------
SCREEN = (1000, 750)
WORLD = (1500, 1500)

PLAYER_SIZE = 50
SPEED = 5

BG_COLOR = (20, 20, 30)
GRID_COLOR = (60, 60, 80)
PLAYER_OUTER = (255, 140, 0)
PLAYER_INNER = (255, 220, 120)
TARGET_COLOR = (255, 60, 60)

fruit_pos = [200, 300]
FRUIT_RADIUS = 10
FRUIT_COLOR = (0, 255, 100)

# ---------------- INIT ----------------
pygame.init()
screen = pygame.display.set_mode(SCREEN)
pygame.display.set_caption("Blob Arena")

world_surface = pygame.Surface(WORLD)
clock = pygame.time.Clock()

player = pygame.Rect(
    WORLD[0] // 2 - PLAYER_SIZE // 2,
    WORLD[1] // 2 - PLAYER_SIZE // 2,
    PLAYER_SIZE,
    PLAYER_SIZE
)

# ---------------- DRAW GRID ----------------
def draw_grid(surface, spacing=40):
    surface.fill((30, 30, 45))
    for x in range(0, WORLD[0], spacing):
        pygame.draw.line(surface, GRID_COLOR, (x, 0), (x, WORLD[1]))
    for y in range(0, WORLD[1], spacing):
        pygame.draw.line(surface, GRID_COLOR, (0, y), (WORLD[0], y))


# ---------------- CAMERA ----------------
def camera_offset(rect):
    return rect.centerx - SCREEN[0] // 2, rect.centery - SCREEN[1] // 2

# ---------------- MOVEMENT ----------------
def move_player(rect, target):
    dx = target[0] - rect.centerx
    dy = target[1] - rect.centery

    dist = (dx * dx + dy * dy) ** 0.5

    if dist == 0:
        return

    dx /= dist
    dy /= dist

    rect.x = max(0, min(WORLD[0] - rect.width, rect.x + dx * SPEED))
    rect.y = max(0, min(WORLD[1] - rect.height, rect.y + dy * SPEED))

# ---------------- MAIN LOOP ----------------
def main():
    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

        cam_x, cam_y = camera_offset(player)

        fruit_screen_x = fruit_pos[0] - cam_x
        fruit_screen_y = fruit_pos[1] - cam_y

        mouse_screen = pygame.mouse.get_pos()
        mouse_world = (mouse_screen[0] + cam_x, mouse_screen[1] + cam_y)

        move_player(player, mouse_world)

    # --- Draw world ---
        draw_grid(world_surface)

        screen.fill(BG_COLOR)

        view = pygame.Rect(cam_x, cam_y, SCREEN[0], SCREEN[1])
        screen.blit(world_surface, (0, 0), view)
        
        fruit_screen_x = fruit_pos[0] - cam_x
        fruit_screen_y = fruit_pos[1] - cam_y

        pygame.draw.circle(
            screen,
            FRUIT_COLOR,
            (int(fruit_screen_x), int(fruit_screen_y)),
            FRUIT_RADIUS
        )
    # --- Draw target ---
        target_screen = (mouse_world[0] - cam_x, mouse_world[1] - cam_y)
        pygame.draw.circle(screen, TARGET_COLOR, target_screen, 6)

    # --- Draw player ---
        center = (SCREEN[0] // 2, SCREEN[1] // 2)
        pygame.draw.circle(screen, PLAYER_OUTER, center, PLAYER_SIZE // 2)
        pygame.draw.circle(screen, PLAYER_INNER, center, PLAYER_SIZE // 3)

        pygame.display.flip()
        clock.tick(60)

    pygame.quit()


main()