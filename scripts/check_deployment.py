"""Check Render/Vercel settings without printing secrets. No network or mutations."""
import argparse
import json
import os
from urllib.parse import urlparse

from dotenv import dotenv_values

parser = argparse.ArgumentParser()
parser.add_argument('--env-file', help='Private environment file; never commit it')
args = parser.parse_args()
values = {**(dotenv_values(args.env_file) if args.env_file else {}), **os.environ}
errors = []
for key in ['VITE_CLERK_PUBLISHABLE_KEY', 'VITE_API_BASE', 'SECURE_SMTP_CLERK_ISSUER',
            'SECURE_SMTP_CLERK_AUTHORIZED_PARTIES', 'SECURE_SMTP_CORS_ORIGINS', 'SECURE_SMTP_MONGO_URI']:
    if not values.get(key):
        errors.append(f'{key}: missing')
for key in ['VITE_API_BASE', 'SECURE_SMTP_CLERK_ISSUER']:
    value = values.get(key, '')
    parsed = urlparse(value)
    if value and (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.query or parsed.fragment):
        errors.append(f'{key}: requires a real HTTPS address')
for key in ['SECURE_SMTP_CLERK_AUTHORIZED_PARTIES', 'SECURE_SMTP_CORS_ORIGINS']:
    try:
        origins = json.loads(values.get(key, 'null'))
        if not isinstance(origins, list) or not origins:
            raise ValueError()
        for origin in origins:
            parsed = urlparse(origin)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
                raise ValueError()
    except (ValueError, TypeError, AttributeError):
        errors.append(f'{key}: requires a nonempty JSON array of exact HTTPS origins')
uri = values.get('SECURE_SMTP_MONGO_URI', '')
if uri:
    parsed = urlparse(uri)
    if parsed.scheme not in ('mongodb', 'mongodb+srv') or not parsed.username or not parsed.password:
        errors.append('SECURE_SMTP_MONGO_URI: requires an authenticated MongoDB connection URI')
key = values.get('VITE_CLERK_PUBLISHABLE_KEY', '')
if key and not key.startswith(('pk_test_', 'pk_live_')):
    errors.append('VITE_CLERK_PUBLISHABLE_KEY: invalid publishable-key prefix')
for error in errors:
    print('FAIL', error)
if not errors:
    print('PASS basic configuration shape. Real provider login/connectivity still needs verification.')
raise SystemExit(bool(errors))
