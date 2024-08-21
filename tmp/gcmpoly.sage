def polyton(a):
    return int("".join(map(str, a.list()[::-1])), 2)


def ntopoly(a, F):
    return sum(F.gen()^i * F(e) for i, e in enumerate(bin(a)[2:][::-1]))


F.<X> = GF(2^128, modulus=x^128+x^7+x^2+x+1)

a = 12345
b = X^13 + X^12 + X^5 + X^4 + X^3 + 1

assert ntopoly(a, F) == b
assert polyton(b) == a

x_ = 0xfeedfacedeadbeeffeedfacedeadbeef
y_ = 0xb83b533708bf535d0aa6e52980d53b78

print(f"X(x) = {ntopoly(x_, F)}")
print(f"Y(x) = {ntopoly(y_, F)}")
res = polyton(ntopoly(x_, F) * ntopoly(y_, F))
print(f"R(x) = {ntopoly(res, F)}")
print(f"{x_} * {y_} == {res}")
print()
print(ntopoly(297747071055821155530452781502797185025, F))
