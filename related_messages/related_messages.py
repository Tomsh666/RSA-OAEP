import math

from sympy import symbols, solve, resultant, gcd, div, GF


def related_messages_attack(n, c1, c2, e):
    x, y = symbols('x y')

    g1 = x ** e - c1
    g2 = (x + y) ** e - c2
    h_y = resultant(g1, g2, x)
    roots_y = solve(h_y, y)
    alpha = 1
    beta = roots_y[0]

    z = symbols('z')
    poly1 = z ** e - c1
    poly2 = (alpha * z + beta) ** e - c2
    m1 = -gcd(poly1, poly2).coeff(z, 0) % n
    m2 = (alpha * m1 + beta) % n

    mu = math.floor(math.log2(n) / (e ** 2))
    # m1 m2:one of them are useless
    m2 = m2 // 2 ** mu
    return m2
