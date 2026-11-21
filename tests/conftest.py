"""Never run integration tests against the developer's configured customer DB.

Start a disposable MongoDB at 127.0.0.1:27029 before the full suite. Pure unit
checks do not need MongoDB. Temporary uploads/reports are removed on exit.
"""

import os
import tempfile

_test_files = tempfile.TemporaryDirectory(prefix="secure_smtp_tests_")
os.environ.update(
    {
        "SECURE_SMTP_MONGO_URI": "mongodb://127.0.0.1:27029",
        "SECURE_SMTP_MONGO_DB": "secure_smtp_tests",
        "SECURE_SMTP_MONGO_USER": "",
        "SECURE_SMTP_MONGO_PASSWORD": "",
        "SECURE_SMTP_MONGO_AUTH_REQUIRED": "false",
        "SECURE_SMTP_API_KEY": "securesmtp_live_secret_key",
        "SECURE_SMTP_AUTH_REQUIRED": "true",
        "SECURE_SMTP_ENV": "testing",
        "SECURE_SMTP_ENABLE_LIVE_LAB": "true",
        "SECURE_SMTP_CLERK_ISSUER": "",
        "SECURE_SMTP_CLERK_ORG_ID": "",
        "SECURE_SMTP_LOCAL_ADMIN_EMAIL": "",
        "SECURE_SMTP_LOCAL_PASSWORD_HASH": "",
        "SECURE_SMTP_ALERTS_ENABLED": "false",
        "SECURE_SMTP_UPLOAD_DIR": _test_files.name + "/uploads",
        "SECURE_SMTP_REPORTS_DIR": _test_files.name + "/reports",
    }
)
