import os
import traceback
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()
url = os.getenv('SUPABASE_URL')
key = os.getenv('SUPABASE_KEY')
masked = 'MISSING'
if key:
    masked = (key[:8] + '...' + key[-4:]) if len(key) > 12 else ('*' * len(key))
print(f"SUPABASE_URL present: {bool(url)}")
print(f"SUPABASE_KEY present: {bool(key)} ({masked})")

try:
    client = create_client(url, key)
    print('create_client: success')
except Exception:
    print('create_client: exception')
    print(traceback.format_exc())
    raise SystemExit(1)

row = {
    'source_input': 'script_test',
    'target': 'https://example.com/path?q=1',
    'risk_score': 10,
    'confidence_score': 15,
    'risk_level': 'LOW',
    'threat_categories': [],
    'detection': {'source': 'manual_test'},
    'geolocation': {'country': 'N/A'},
    'summary': 'manual supabase insert test'
}

try:
    resp = client.table('scan_history').insert(row).execute()
    print('insert: success')
except Exception:
    print('insert: exception')
    print(traceback.format_exc())

try:
    sel = client.table('scan_history').select('*').order('id', desc=True).limit(3).execute()
    data = sel.data if hasattr(sel, 'data') and sel.data is not None else []
    print(f"select: success row_count={len(data)}")
except Exception:
    print('select: exception')
    print(traceback.format_exc())
