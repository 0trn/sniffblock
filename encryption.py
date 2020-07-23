import hashlib as hlib
from database import *

# custom secret
salt = Group("secrets").get("salt").strip()
auth_salt = Group("secrets").get("auth_salt").strip()

# main hashes:

def sha512(text):
    return hlib.sha512(str(text).encode('utf-8')).hexdigest()

def sha256(text):
    return hlib.sha256(str(text).encode('utf-8')).hexdigest()

def encrypt(text):
    return sha256(text+salt)+sha512(text+salt+text)+sha256(salt+text)

# helpers:

def limiter(text, qoef):
    return text[qoef%len(text)]

def num_of(character):
    return {
    '0':2,
    '1':3,
    '2':5,
    '3':7,
    '4':11,
    '5':13,
    '6':17,
    '7':19,
    '8':23,
    '9':29,
    'a':31,
    'b':37,
    'c':41,
    'd':43,
    'e':47,
    'f':53,
    }[character]

# messages:

def message_encrypt(message, _from, _to, _chatroomid):
    emsg = ''
    current_pos = 0;
    ecr_from = encrypt(_from)
    ecr_to = encrypt(_to)+'d'
    ecr_chatroomid = encrypt(_chatroomid)+'ef'
    for char in message:
        _f_current = num_of(limiter(ecr_from, current_pos))
        _t_current = num_of(limiter(ecr_to, current_pos))
        _c_current = num_of(limiter(ecr_chatroomid, current_pos))
        calculated = 300 + ord(char) + _f_current + _t_current + _c_current
        emsg += chr(calculated)
        current_pos += 1;
    return emsg

def message_decrypt(message, _from, _to, _chatroomid):
    emsg = ''
    current_pos = 0;
    ecr_from = encrypt(_from)
    ecr_to = encrypt(_to)+'d'
    ecr_chatroomid = encrypt(_chatroomid)+'ef'
    for char in message:
        _f_current = num_of(limiter(ecr_from, current_pos))
        _t_current = num_of(limiter(ecr_to, current_pos))
        _c_current = num_of(limiter(ecr_chatroomid, current_pos))
        calculated = - 300 + ord(char) - _f_current - _t_current - _c_current
        emsg += chr(calculated)
        current_pos += 1;
    return emsg