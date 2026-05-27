"""Generate structured threat briefs from Snowflake vulnerability data."""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, Encoding, PrivateFormat, NoEncryption,
)
import snowflake.connector

logger = logging.getLogger(__name__)
REPORTS_DIR = Path(__file__).parent.parent / "reports"


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


def _fetch(cur, sql: str) -> list[dict]:
    cur.execute(sql)
    cols = [d[0].lower() for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _ensure_tables(cur) -> None:
    cur.execute("CREATE SCHEMA IF NOT EXISTS ANALYTICS.SECURITY")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ANALYTICS.SECURITY.THREAT_BRIEFS (
            BRIEF_ID        VARCHAR(36),
            GENERATED_AT    TIMESTAMP_TZ,
            CVE_COUNT       INTEGER,
            CRITICAL_COUNT  INTEGER,
            TOP_ECOSYSTEM   VARCHAR(100),
            PIPELINE_STATUS VARCHAR(50),
            BRIEF_TEXT      TEXT
        )
    """)


def generate_threat_brief() -> str:
    """Query Snowflake, render a threat brief, persist to Snowflake and disk."""
    conn = _build_conn()
    cur  = conn.cursor()
    _ensure_tables(cur)

    # ── Data queries ──────────────────────────────────────────────────────────
    top5 = _fetch(cur, """
        SELECT advisory_id, cve_id, summary, severity, cvss_score,
               composite_risk_score, age_bucket, days_since_published,
               vulnerability_category
        FROM ANALYTICS.MARTS.MART_CRITICAL_VULNERABILITIES
        ORDER BY composite_risk_score DESC
        LIMIT 5
    """)

    top3_eco = _fetch(cur, """
        SELECT ecosystem_name, avg_risk_score, critical_count, total_vulnerabilities
        FROM ANALYTICS.MARTS.MART_ECOSYSTEM_RISK
        ORDER BY avg_risk_score DESC
        LIMIT 3
    """)

    sev_summary = _fetch(cur, """
        SELECT severity,
               SUM(total_count)    AS total,
               SUM(critical_count) AS critical_sum
        FROM ANALYTICS.MARTS.MART_VULNERABILITY_SUMMARY
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1 WHEN 'high'   THEN 2
                WHEN 'medium'   THEN 3 WHEN 'low'    THEN 4
                ELSE 5
            END
    """)

    age_summary = _fetch(cur, """
        SELECT age_bucket, SUM(total_count) AS total
        FROM ANALYTICS.MARTS.MART_VULNERABILITY_SUMMARY
        GROUP BY age_bucket
        ORDER BY
            CASE age_bucket
                WHEN 'new' THEN 1 WHEN 'recent' THEN 2
                WHEN 'aging' THEN 3 WHEN 'chronic' THEN 4
                ELSE 5
            END
    """)

    health = _fetch(cur, "SELECT * FROM ANALYTICS.MARTS.MART_PIPELINE_HEALTH")[0]

    eco_count_row = _fetch(cur,
        "SELECT COUNT(DISTINCT ecosystem_name) AS n FROM ANALYTICS.MARTS.MART_ECOSYSTEM_RISK"
    )[0]

    # ── Derived values ────────────────────────────────────────────────────────
    pipeline_status = health["pipeline_status"]
    last_ingested   = str(health["last_ingested_at"])[:19]
    total_rows      = health["total_rows"]
    eco_count       = eco_count_row["n"]
    total_cves      = sum(r["total"] for r in sev_summary)
    critical_count  = sum(r["critical_sum"] for r in sev_summary)
    top_eco         = top3_eco[0]["ecosystem_name"] if top3_eco else "N/A"
    max_score       = top5[0]["composite_risk_score"] if top5 else 0
    age_map         = {r["age_bucket"]: r["total"] for r in age_summary}
    chronic_cnt     = age_map.get("chronic", 0)
    top_eco_row     = top3_eco[0] if top3_eco else {}

    # ── Threat cards ──────────────────────────────────────────────────────────
    W = 47
    cards = []
    for i, v in enumerate(top5, 1):
        cve  = v.get("cve_id") or "N/A"
        summ = (v.get("summary") or "")[:W]
        cards.append(
            f"  ┌{'─'*W}┐\n"
            f"  │ #{i}  {cve:<{W-5}}│\n"
            f"  │     Score:    {str(v['composite_risk_score']):<{W-12}}│\n"
            f"  │     Severity: {str(v['severity']):<{W-12}}│\n"
            f"  │     Age:      {str(v['days_since_published'])+' days':<{W-12}}│\n"
            f"  │     Category: {str(v['vulnerability_category']):<{W-12}}│\n"
            f"  │     Summary:  {summ:<{W-12}}│\n"
            f"  └{'─'*W}┘"
        )

    # ── Ecosystem ranking ─────────────────────────────────────────────────────
    eco_lines = "\n".join(
        f"  {i}. {r['ecosystem_name']:<20} avg risk {r['avg_risk_score']},  "
        f"{r['critical_count']} critical CVEs"
        for i, r in enumerate(top3_eco, 1)
    )

    # ── Recommended actions ───────────────────────────────────────────────────
    actions: list[str] = []
    if chronic_cnt > 10:
        actions.append(
            f"  ⚠️  {chronic_cnt} vulnerabilities unpatched >1 year. "
            "Immediate patch review required."
        )
    if top_eco_row.get("critical_count", 0) > 5:
        actions.append(
            f"  🔴 {top_eco} has {top_eco_row['critical_count']} critical CVEs. "
            f"Audit all {top_eco} dependencies."
        )
    if pipeline_status != "healthy":
        actions.append(
            "  🚨 Pipeline unhealthy — data may be stale. Investigate ingestion job."
        )
    actions.append(
        "  ✅ Run dbt test to validate data contract compliance before next report."
    )

    sev_lines = "\n".join(
        f"  {r['severity'].capitalize():<12} {r['total']}" for r in sev_summary
    )
    sep = "═" * 55
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    brief = f"""{sep}
WEEKLY SECURITY THREAT BRIEF
Generated: {now}
Data as of: {last_ingested} UTC
{sep}

EXECUTIVE SUMMARY
Platform analyzed {total_rows} vulnerabilities.
{critical_count} critical threats detected across {eco_count} ecosystems.
Pipeline status: {pipeline_status}.

TOP 5 CRITICAL THREATS

{chr(10).join(cards)}

ECOSYSTEM RISK RANKING

{eco_lines}

SEVERITY BREAKDOWN

{sev_lines}

TREND INDICATORS
  Age distribution: {age_map.get('new', 0)} new / {age_map.get('recent', 0)} recent / {age_map.get('aging', 0)} aging / {age_map.get('chronic', 0)} chronic
  Highest single risk score this period: {max_score}
  Most affected ecosystem: {top_eco}

RECOMMENDED ACTIONS

{chr(10).join(actions)}

{sep}
Generated by Cloud Security Intelligence Platform
Infrastructure: Snowflake + dbt + Terraform + Snowpark
{sep}"""

    # ── Persist to Snowflake ──────────────────────────────────────────────────
    brief_id     = str(uuid.uuid4())
    generated_at = datetime.now(timezone.utc).isoformat()
    cur.execute("""
        INSERT INTO ANALYTICS.SECURITY.THREAT_BRIEFS
            (BRIEF_ID, GENERATED_AT, CVE_COUNT, CRITICAL_COUNT,
             TOP_ECOSYSTEM, PIPELINE_STATUS, BRIEF_TEXT)
        VALUES (%s, %s::TIMESTAMP_TZ, %s, %s, %s, %s, %s)
    """, (brief_id, generated_at, total_cves, critical_count,
          top_eco, pipeline_status, brief))

    # ── Save to local file ────────────────────────────────────────────────────
    REPORTS_DIR.mkdir(exist_ok=True)
    date_str    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report_path = REPORTS_DIR / f"threat_brief_{date_str}.txt"
    report_path.write_text(brief, encoding="utf-8")

    print(brief)
    print(f"\n[Saved] {report_path}")
    logger.info("Threat brief %s saved to Snowflake and %s", brief_id, report_path)

    cur.close()
    conn.close()
    return brief


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    generate_threat_brief()
