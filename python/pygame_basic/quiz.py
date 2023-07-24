import pygame
import numpy as np

pygame.init()

screen_height = 640
screen_width = 480

screen = pygame.display.set_mode((screen_width, screen_height))

background = pygame.image.load("D:/coding/python/pygame_basic/background.png")

character = pygame.image.load("D:/coding/python/pygame_basic/character.png")
character_size = character.get_rect().size

enemy = pygame.image.load("D:/coding/python/pygame_basic/enemy.png")
enemy_size = enemy.get_rect().size
pygame.display.set_caption("avoid game")

clock = pygame.time.Clock()

character_width = character_size[0]
character_height = character_size[1]
enemy_width = enemy_size[0]
enemy_height = enemy_size[1]

character_x_position = screen_width / 2 - character_width / 2
character_y_position = screen_height - character_height

enemy_x_position = 0
enemy_y_position = 0

character_speed = 0.6
enemy_speed = 0.6

start_ticks = pygame.time.get_ticks()

to_x = 0
to_y = 0

enemy_x_position = np.random.randint(35,445)

running = True
while running:

    dt = clock.tick(30)

    if enemy_y_position == screen_height:
        enemy_x_position = np.random.randint(35,445)
        enemy_y_position = 0

    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False

        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_LEFT:
                to_x -= character_speed
            elif event.key == pygame.K_RIGHT:
                to_x += character_speed

        if event.type == pygame.KEYUP:
            if event.key == pygame.K_LEFT or event.key == pygame.K_RIGHT:
                to_x = 0
    
    character_x_position += to_x * dt
    
    enemy_y_position += 40

    if character_x_position < 0:
        character_x_position = character_width
    if character_x_position > screen_width - character_width:
        character_x_position = screen_width - character_width

    character_rect = character.get_rect()
    character_rect.left = character_x_position
    character_rect.top = character_y_position

    enemy_rect = enemy.get_rect()
    enemy_rect.left = enemy_x_position
    enemy_rect.top = enemy_y_position

    if character_rect.colliderect(enemy_rect):
        print("colliderect!")
        running = False

    screen.blit(background, (0,0))

    screen.blit(character, (character_x_position, character_y_position))

    screen.blit(enemy, (enemy_x_position, enemy_y_position))
    
    pygame.display.update()

pygame.time.delay(2000)

pygame.quit()