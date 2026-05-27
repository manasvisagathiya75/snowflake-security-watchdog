{{ config(contract={"enforced": true}) }}

with enriched as (

    select * from {{ ref('int_vulnerabilities_enriched') }}

),

critical as (

    select
        advisory_id,
        cve_id,
        summary,
        severity,
        cvss_score,
        composite_risk_score,
        age_bucket,
        days_since_published,
        vulnerability_category,
        published_at

    from enriched
    where composite_risk_score >= 9.0

)

select * from critical
order by composite_risk_score desc
