

# This file was *autogenerated* from the file gcmpoly.sage
from sage.all_cmdline import *   # import sage library

_sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_128 = Integer(128); _sage_const_7 = Integer(7); _sage_const_12345 = Integer(12345); _sage_const_13 = Integer(13); _sage_const_12 = Integer(12); _sage_const_5 = Integer(5); _sage_const_4 = Integer(4); _sage_const_3 = Integer(3); _sage_const_0xfeedfacedeadbeeffeedfacedeadbeef = Integer(0xfeedfacedeadbeeffeedfacedeadbeef); _sage_const_0xb83b533708bf535d0aa6e52980d53b78 = Integer(0xb83b533708bf535d0aa6e52980d53b78); _sage_const_297747071055821155530452781502797185025 = Integer(297747071055821155530452781502797185025)
def polyton(a):
    return int("".join(map(str, a.list()[::-_sage_const_1 ])), _sage_const_2 )


def ntopoly(a, F):
    return sum(F.gen()**i * F(e) for i, e in enumerate(bin(a)[_sage_const_2 :][::-_sage_const_1 ]))


F = GF(_sage_const_2 **_sage_const_128 , modulus=x**_sage_const_128 +x**_sage_const_7 +x**_sage_const_2 +x+_sage_const_1 , names=('X',)); (X,) = F._first_ngens(1)

a = _sage_const_12345 
b = X**_sage_const_13  + X**_sage_const_12  + X**_sage_const_5  + X**_sage_const_4  + X**_sage_const_3  + _sage_const_1 

assert ntopoly(a, F) == b
assert polyton(b) == a

x_ = _sage_const_0xfeedfacedeadbeeffeedfacedeadbeef 
y_ = _sage_const_0xb83b533708bf535d0aa6e52980d53b78 

print(f"X(x) = {ntopoly(x_, F)}")
print(f"Y(x) = {ntopoly(y_, F)}")
res = polyton(ntopoly(x_, F) * ntopoly(y_, F))
print(f"R(x) = {ntopoly(res, F)}")
print(f"{x_} * {y_} == {res}")
print()
print(ntopoly(_sage_const_297747071055821155530452781502797185025 , F))

