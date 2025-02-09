from fastapi import HTTPException, Request
from functools import wraps
from dotenv import load_dotenv
import os
# tow API keys for admin and user

load_dotenv()

# Get API keys from environment variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
USER_API_KEY = os.getenv("USER_API_KEY")

# Decorator to check for API key and role


def api_key_required(role: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            key = request.headers.get("X-API-Key")
            # Check Api key
            if not key:
                raise HTTPException(status_code=403, detail="API Key required")
            if role == "admin":
                if key != ADMIN_API_KEY:
                    raise HTTPException(status_code=403, detail="Forbidden: Invalid Admin API Key")
            elif role == "user":
                if key != USER_API_KEY:
                    raise HTTPException(status_code=403, detail="Forbidden: Invalid User API Key")
            else:
                raise HTTPException(status_code=400, detail="Invalid role specified")

            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
