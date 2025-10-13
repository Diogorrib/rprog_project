import secrets

SEED_SIZE = 128 // 8
CHUNK_SIZE = 32 // 8

def generate_seed():
    return secrets.token_bytes(SEED_SIZE)

def generate_prng_seed():
    return secrets.token_bytes(SEED_SIZE)

def seed_to_int(seed):
    return int.from_bytes(seed, byteorder='big')

def int_to_seed(value, size=CHUNK_SIZE):
    return value.to_bytes(size, byteorder='big')

def seed_to_hex(seed):
    return seed.hex()

def get_n_chunks(n_bytes, chunk_size=CHUNK_SIZE):
    return n_bytes // chunk_size
