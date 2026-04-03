import os
from typing import Optional

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

REQUEST_TIMEOUT_SECONDS = 15
CACHE_TTL_SECONDS = 600

_supabase_client: Optional[Client] = None


def get_supabase_client() -> Optional[Client]:
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if not SUPABASE_URL or not SUPABASE_KEY:
        return None

    if not SUPABASE_URL.startswith("http"):
        return None

    if SUPABASE_URL == "your_url" or SUPABASE_KEY == "your_key":
        return None

    _supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
    return _supabase_client
