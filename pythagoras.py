#!/bin/python
from math import sqrt

print("a^2 + b^2 = c^2")

leg1 = input("Leg1 (a): ")
leg2 = input("Leg2 (b): ")

hypotenuse = sqrt((int(leg1) ** 2) + (int(leg2) ** 2))
print(hypotenuse)
