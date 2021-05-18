from hashlib import *
from pwn import *
import string

def brute(s1, s2):
    charset = string.digits + string.letters #+ string.punctuation
    sol = iters.bruteforce(lambda x: sha256(x+s1).hexdigest() == s2, charset, 4)
    print (sol)
    return sol
