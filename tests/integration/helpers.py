import string
from random import randrange, choice, randint


def generate_sequence(length: int):
    return "".join(choice(string.ascii_letters) for _ in range(length))
