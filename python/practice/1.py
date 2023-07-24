import matplotlib.pyplot as plt
import numpy as np

# 초기값 설정
v = 30 # 초기 속도 (m/s)
theta = np.pi/4 # 던지는 각도 (radian)
g = 9.81 # 중력 가속도 (m/s^2)
t = np.linspace(0, 6, 100) # 시간 (0초부터 6초까지, 100등분)

# x, y 좌표 계산
x = v * np.cos(theta) * t
y = v * np.sin(theta) * t - 0.5 * g * t**2

# 그래프 그리기
plt.plot(x, y)
plt.xlabel('x (m)')
plt.ylabel('y (m)')
plt.title('Projectile Motion')
plt.show()
