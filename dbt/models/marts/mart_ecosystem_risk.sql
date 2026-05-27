with enriched as (

    select * from {{ ref('int_vulnerabilities_enriched') }}

),

raw_advisories as (

    select
        GHSA_ID,
        AFFECTED_PACKAGES
    from {{ source('raw', 'RAW_GITHUB_ADVISORIES') }}
    where AFFECTED_PACKAGES is not null

),

joined as (

    select
        e.advisory_id,
        e.severity,
        e.composite_risk_score,
        r.AFFECTED_PACKAGES
    from enriched e
    inner join raw_advisories r on r.GHSA_ID = e.advisory_id

),

flattened as (

    select
        j.advisory_id,
        j.severity,
        j.composite_risk_score,
        f.value:package:ecosystem::varchar as ecosystem_name
    from joined j,
         lateral flatten(input => j.AFFECTED_PACKAGES) f
    where f.value:package:ecosystem::varchar is not null
      and f.value:package:ecosystem::varchar != ''

),

aggregated as (

    select
        ecosystem_name,
        count(distinct advisory_id)                             as total_vulnerabilities,
        sum(case when severity = 'critical' then 1 else 0 end) as critical_count,
        sum(case when severity = 'high'     then 1 else 0 end) as high_count,
        round(avg(composite_risk_score), 2)                    as avg_risk_score,
        max(composite_risk_score)                              as max_risk_score

    from flattened
    group by ecosystem_name

)

select * from aggregated
order by avg_risk_score desc
