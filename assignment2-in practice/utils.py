import re


import hashlib
def id_hashed(url):
    url_bytes = url.encode('utf-8') # string to byte
    hash_object = hashlib.sha256(url_bytes) # Hash the byte string using SHA-256
    print(hash_object)
    print(type(hash_object))
    # Get the hexadecimal representation of the hash
    hash_hex = hash_object.hexdigest()
    return hash_hex[:8]
def build_result(code, value): # the form of returning values, like json
    return {"code": code, "value": value}

def is_valid_url(str): # use regrex to judge if a given url is given
    url_pattern = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
    # We got insight from https://stackoverflow.com/questions/161738/what-is-the-best-regular-expression-to-check-if-a-string-is-a-valid-url
    return re.match(url_pattern, str) is not None

def generate_unique_id(url): # generate unique id
    return id_hashed(url)

