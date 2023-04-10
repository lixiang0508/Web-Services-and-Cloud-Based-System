
import re
#from snowflake import idworker
import uuid
import snowflake.client
def build_result(code, value):
    return {"code": code, "value": value}

def is_valid_url(str):
    url_pattern = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
    return re.match(url_pattern, str) is not None

def generate_unique_id():
    return uuid.uuid1().hex
