import uuid

def new_request_id():
    """Returns a random, collision-resistant request id string."""
    return str(uuid.uuid4())
