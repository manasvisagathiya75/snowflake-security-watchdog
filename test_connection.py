import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PrivateFormat,
    NoEncryption,
)
import snowflake.connector

load_dotenv()

key_path = os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH")
passphrase_raw = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE") or ""
passphrase = passphrase_raw.encode() if passphrase_raw else None

with open(key_path, "rb") as f:
    private_key = load_pem_private_key(f.read(), password=passphrase)

private_key_der = private_key.private_bytes(
    encoding=Encoding.DER,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption(),
)

conn = snowflake.connector.connect(
    account=os.getenv("SNOWFLAKE_ACCOUNT"),
    user=os.getenv("SNOWFLAKE_USER"),
    private_key=private_key_der,
    database=os.getenv("SNOWFLAKE_DATABASE"),
    warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
    role=os.getenv("SNOWFLAKE_ROLE"),
)

cur = conn.cursor()
cur.execute(
    "SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_WAREHOUSE(), CURRENT_DATABASE()"
)
row = cur.fetchone()
print(f"User:      {row[0]}")
print(f"Role:      {row[1]}")
print(f"Warehouse: {row[2]}")
print(f"Database:  {row[3]}")
cur.close()
conn.close()
