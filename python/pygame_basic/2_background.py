import pygame

pygame.init()

screen_width = 480
screen_height = 640

screen = pygame.display.set_mode((screen_width, screen_height))

background = pygame.image.load("D:/coding/python/pygame_basic/background.png")
pygame.display.set_caption("offRo")

running = True
while running:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False

    screen.fill((0, 125, 255))
    #screen.blit(background, (0,0))

    pygame.display.update()

pygame.quit() 