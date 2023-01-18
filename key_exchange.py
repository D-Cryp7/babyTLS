from random import randint
from params import *
from ecc import *

class KEY_EXCHANGE:
    def __init__(self, name, code):
        if name == "DHE":
            group = DHE_SUPPORTED_GROUPS[code]
            self.g = group["g"]
            self.p = group["p"]
        else: # ECDHKE for default
            curve = ECDHE_SUPPORTED_CURVES[code]
            self.E = {"a": curve["a"], "b": curve["b"], "p": curve["p"], "n": curve["n"]}
            self.G = curve["G"]
            if curve["type"] == "W":
                self.multiply = Weierstrass().multiply
            else: # Montgomery by default
                self.multiply = Montgomery().multiply
        self.name = name
        self.code = code
        
    def generate_public_key(self):
        if self.name == "DHE":
            s = randint(2, self.p - 2)
            pk = pow(self.g, s, self.p)
        else: # ECDHE for default
            s = randint(2, self.E["n"] - 1)
            pk = self.multiply(s, self.G, self.E)
        self.s = s # store the private key
        return pk
        
    def generate_shared_secret(self, pk):
        if self.name == "DHE":
            shared_secret = pow(pk, self.s, self.p)
        else: # ECDHE for default
            shared_secret = self.multiply(self.s, pk, self.E)[0]
        return shared_secret