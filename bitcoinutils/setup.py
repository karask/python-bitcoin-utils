
NETWORK = None

networks = {'mainnet', 'testnet'}

def setup(network='mainnet'):
    global NETWORK
    NETWORK = network
    return NETWORK


def get_network():
    global NETWORK
    return NETWORK


def is_mainnet():
    global NETWORK
    if NETWORK == 'mainnet':
        return True
    else:
        return False
