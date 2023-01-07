from Crypto.Util.number import inverse
from copy import deepcopy

O = "Origin" # for Weierstrass implementation

def eea(r0, r1):
    if r0 == 0:
        return (r1, 0, 1)
    else:
        g, s, t = eea(r1 % r0, r0)
        return (g, t - (r1 // r0) * s, s)

class Weierstrass:
    def add(self, P, Q, E):
        a, p = E["a"], E["p"]
        if (P == O):
            return Q
        elif (Q == O):
            return P
        elif ((P[0] == Q[0]) and (P[1] == p - Q[1])):
            return O
        else:
            if (P[0] == Q[0] and P[1] == Q[1]):
                S = ((3 * (pow(P[0], 2)) + a) * eea(2 * P[1], p)[1]) % p
            else:
                S = ((Q[1] - P[1]) * eea((Q[0] - P[0]) % p, p)[1]) % p
            x3 = (pow(S, 2) - P[0] - Q[0]) % p
            y3 = (S * (P[0] - x3) - P[1]) % p
            Q[0], Q[1] = x3, y3
            return [x3, y3]


    def multiply(self, s, P, E):
        s = list(int(k) for k in "{0:b}".format(s))
        del s[0]
        T = list(deepcopy(P))
        for i in range(len(s)):
            T = self.add(T, T, E)
            if (s[i] == 1):
                T = self.add(P, T, E)
        return T

class Montgomery:
    def add(self, P, Q, E):
        a, b, p = E["a"], E["b"], E["p"]
        alpha = inverse(Q[0] - P[0], p) * (Q[1] - P[1]) % p
        x = (b * pow(alpha, 2) - a - P[0] - Q[0]) % p
        y = (alpha * (P[0] - x) - P[1]) % p
        return [x, y]

    def double(self, P, E):
        a, b, p = E["a"], E["b"], E["p"]
        alpha = inverse(2 * b * P[1], p) * (3 * pow(P[0], 2) + 2 * a * P[0] + 1) % p
        x = (b * pow(alpha, 2) - a - 2 * P[0]) % p
        y = (alpha * (P[0] - x) - P[1]) % p
        return [x, y]

    def multiply(self, s, P, E):
        s = list(int(k) for k in "{0:b}".format(s))
        del s[0]
        T = list(deepcopy(P))
        R = [T, self.double(T, E)]
        for i in range(len(s)):
            if (s[i] == 0):
                R = [self.double(R[0], E), self.add(R[0], R[1], E)]
            else:
                R = [self.add(R[0], R[1], E), self.double(R[1], E)]
        return R[0]