"""Test the deployment initializer against disposable MongoDB with auth enabled."""

import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import OperationFailure
from rehearse_pilot import ROOT, disposable_mongo


def rehearse():
    admin_password, app_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory() as directory:
        with disposable_mongo(Path(directory), authenticated=True) as (uri, bootstrap):
            # MongoDB's localhost exception permits creating the first administrator.
            bootstrap.admin.command("createUser", "rehearsal_admin", pwd=admin_password,
                                    roles=[{"role": "root", "db": "admin"}])
            environment = {
                **os.environ,
                "MONGO_INITDB_ROOT_USERNAME": "rehearsal_admin",
                "MONGO_INITDB_ROOT_PASSWORD": admin_password,
                "SECURE_SMTP_MONGO_USER": "pilot_app",
                "SECURE_SMTP_MONGO_PASSWORD": app_password,
            }
            program = (
                "db.getSiblingDB('admin').auth(process.env.MONGO_INITDB_ROOT_USERNAME, "
                "process.env.MONGO_INITDB_ROOT_PASSWORD); load("
                + json.dumps(str(ROOT / "docker/mongo-init.js")) + ");"
            )
            subprocess.run(["mongosh", uri, "--quiet", "--norc", "--eval", program],
                           env=environment, check=True, capture_output=True, timeout=30)
            with MongoClient(uri, username="pilot_app", password=app_password,
                             authSource="secure_smtp_pilot") as app:
                records = app.secure_smtp_pilot.permissions_rehearsal
                records.create_index("record", unique=True)
                records.insert_one({"record": "owned"})
                assert records.find_one({"record": "owned"})
                assert records.delete_one({"record": "owned"}).deleted_count == 1
                denied_operations = [
                    lambda: app.other_organization.secrets.find_one({}),
                    lambda: app.admin.command("createUser", "escalation", pwd="fixture",
                                              roles=[{"role": "root", "db": "admin"}]),
                    lambda: app.secure_smtp_pilot.command("createUser", "extra", pwd="fixture",
                                                         roles=["readWrite"]),
                ]
                for operation in denied_operations:
                    try:
                        operation()
                    except OperationFailure as error:
                        assert error.code == 13
                    else:
                        raise AssertionError("Application account exceeded its database permissions")
    print("Passed application database CRUD/index creation; foreign database and user administration denied.")


if __name__ == "__main__":
    rehearse()
