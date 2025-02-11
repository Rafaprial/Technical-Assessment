from fastapi import HTTPException, Request, Header
from functools import wraps
from dotenv import load_dotenv
import os
# tow API keys for admin and user

load_dotenv()

# Get API keys from environment variables
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
USER_API_KEY = os.getenv("USER_API_KEY")

# Decorator to check for API key and role

async def api_key_required(x_api_key: str = Header(...)):
    if x_api_key == ADMIN_API_KEY:
        return "admin"
    elif x_api_key == USER_API_KEY:
        return "user"
    else:
        raise HTTPException(status_code=403, detail="Invalid API Key")
