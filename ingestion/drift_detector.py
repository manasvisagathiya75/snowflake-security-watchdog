"""Detect Terraform infrastructure drift by running terraform plan."""

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PrivateFormat, NoEncryption,
)
import snowflake.connector

logger = logging.getLogger(__name__)
TERRAFORM_DIR = Path(__file__).parent.parent / "terraform"
_TF_BIN_DIR   = TERRAFORM_DIR / "bin"


def _build_conn():
    load_dotenv()
    with open(os.environ["SNOWFLAKE_PRIVATE_KEY_PATH"], "rb") as f:
        key = load_pem_private_key(f.read(), password=None)
    pk_der = key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    return snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_ACCOUNT"],
        user=os.environ["SNOWFLAKE_USER"],
        private_key=pk_der,
        warehouse=os.environ["SNOWFLAKE_WAREHOUSE"],
        database="ANALYTICS",
        role="ACCOUNTADMIN",
    )


def _ensure_table(cur) -> None:
    cur.execute("CREATE SCHEMA IF NOT EXISTS ANALYTICS.SECURITY")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ANALYTICS.SECURITY.INFRASTRUCTURE_DRIFT (
            CHECKED_AT           TIMESTAMP_TZ,
            DRIFT_DETECTED       BOOLEAN,
            RESOURCES_TO_ADD     INTEGER,
            RESOURCES_TO_CHANGE  INTEGER,
            RESOURCES_TO_DESTROY INTEGER,
            DRIFT_DETAILS        VARIANT,
            RAW_PLAN_OUTPUT      TEXT
        )
    """)


def _parse_plan(stdout: str) -> dict:
    to_add = to_change = to_destroy = 0
    changed: list[str] = []

    m = re.search(
        r"Plan:\s*(\d+) to add,\s*(\d+) to change,\s*(\d+) to destroy", stdout
    )
    if m:
        to_add, to_change, to_destroy = int(m.group(1)), int(m.group(2)), int(m.group(3))

    for line in stdout.splitlines():
        hit = re.match(r"\s*[#~+\-]\s+([\w.]+)\s+will be", line)
        if hit:
            changed.append(hit.group(1))

    return {
        "to_add":     to_add,
        "to_change":  to_change,
        "to_destroy": to_destroy,
        "resources":  list(dict.fromkeys(changed)),   # deduplicate, preserve order
    }


def run_drift_detection() -> bool:
    """Run terraform plan and record results in SECURITY.INFRASTRUCTURE_DRIFT.

    Returns True if drift was detected, False otherwise.
    Handles exit codes: 0 = clean, 2 = drift, 1 = error.
    """
    load_dotenv()

    env = os.environ.copy()
    if _TF_BIN_DIR.exists():
        env["PATH"] = str(_TF_BIN_DIR) + os.pathsep + env.get("PATH", "")
    # Unset provider env vars that conflict with main.tf attribute definitions
    for k in ("SNOWFLAKE_PRIVATE_KEY_PATH", "SNOWFLAKE_ACCOUNT",
              "SNOWFLAKE_USER", "SNOWFLAKE_ROLE"):
        env.pop(k, None)
    env.update({
        "TF_VAR_snowflake_user":             os.getenv("SNOWFLAKE_USER", ""),
        "TF_VAR_snowflake_role":             "ACCOUNTADMIN",
        "TF_VAR_snowflake_private_key_path": os.getenv("SNOWFLAKE_PRIVATE_KEY_PATH", ""),
        "TF_VAR_snowflake_account":          os.getenv("SNOWFLAKE_ACCOUNT", ""),
    })

    tf_exe = str(_TF_BIN_DIR / "terraform.exe") if (_TF_BIN_DIR / "terraform.exe").exists() else "terraform"
    result = subprocess.run(
        [tf_exe, "plan", "-var-file=terraform.tfvars",
         "-detailed-exitcode", "-no-color"],
        capture_output=True,
        text=True,
        cwd=str(TERRAFORM_DIR),
        env=env,
    )

    exit_code = result.returncode
    stdout    = result.stdout
    stderr    = result.stderr

    if exit_code == 1:
        logger.error("Terraform plan error:\n%s", stderr)
        print(f"FAIL Terraform error - plan failed:\n{stderr[:800]}")
        return False

    drift_detected = (exit_code == 2)
    parsed = _parse_plan(stdout)

    # ── Write to Snowflake ────────────────────────────────────────────────────
    conn = _build_conn()
    cur  = conn.cursor()
    _ensure_table(cur)
    cur.execute("""
        INSERT INTO ANALYTICS.SECURITY.INFRASTRUCTURE_DRIFT
            (CHECKED_AT, DRIFT_DETECTED, RESOURCES_TO_ADD,
             RESOURCES_TO_CHANGE, RESOURCES_TO_DESTROY,
             DRIFT_DETAILS, RAW_PLAN_OUTPUT)
        SELECT %s::TIMESTAMP_TZ, %s, %s, %s, %s, PARSE_JSON(%s), %s
    """, (
        datetime.now(timezone.utc).isoformat(),
        drift_detected,
        parsed["to_add"],
        parsed["to_change"],
        parsed["to_destroy"],
        json.dumps({"changed_resources": parsed["resources"]}),
        stdout[:16000],
    ))
    cur.close()
    conn.close()

    # ── Console output ────────────────────────────────────────────────────────
    if drift_detected:
        print("WARN INFRASTRUCTURE DRIFT DETECTED")
        print("   Resources drifted from Terraform state:")
        if parsed["resources"]:
            for r in parsed["resources"]:
                print(f"   - {r}")
        else:
            print(f"   - {parsed['to_add']} to add, "
                  f"{parsed['to_change']} to change, "
                  f"{parsed['to_destroy']} to destroy")
        print(
            "\n   This may indicate unauthorized manual changes or\n"
            "   privilege escalation outside of IaC controls."
        )
    else:
        print("OK Infrastructure clean -- no drift detected")

    return drift_detected


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    run_drift_detection()
