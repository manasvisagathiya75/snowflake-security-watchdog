with source as (

    select * from {{ source('raw', 'RAW_GITHUB_ADVISORIES') }}
    where WITHDRAWN_AT is null

),

renamed as (

    select
        GHSA_ID                    as advisory_id,
        CVE_ID                     as cve_id,
        SUMMARY                    as summary,
        DESCRIPTION                as description,
        lower(SEVERITY)            as severity,
        CVSS_SCORE::float          as cvss_score,
        PUBLISHED_AT::timestamp_tz as published_at,
        UPDATED_AT::timestamp_tz   as updated_at,
        INGESTED_AT                as ingested_at

    from source

),

enriched as (

    select
        *,
        coalesce(cvss_score >= 9.0, false)                       as is_critical,
        datediff('day', published_at::date, current_date())      as days_since_published

    from renamed

)

select * from enriched
