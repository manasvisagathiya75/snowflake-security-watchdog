with staged as (

    select * from {{ ref('stg_github_advisories') }}

),

bucketed as (

    select
        *,
        case
            when days_since_published <= 30  then 'new'
            when days_since_published <= 90  then 'recent'
            when days_since_published <= 365 then 'aging'
            else                                  'chronic'
        end as age_bucket

    from staged

),

enriched as (

    select
        *,

        case age_bucket
            when 'new'     then 1.0
            when 'recent'  then 1.2
            when 'aging'   then 1.5
            when 'chronic' then 2.0
        end as age_risk_multiplier,

        case
            when summary ilike '%injection%'
              or summary ilike '%rce%'
              or summary ilike '%remote code%'     then 'code_execution'
            when summary ilike '%privilege%'
              or summary ilike '%escalation%'      then 'privilege_escalation'
            when summary ilike '%disclosure%'
              or summary ilike '%exposure%'
              or summary ilike '%leak%'            then 'data_exposure'
            when summary ilike '%bypass%'
              or summary ilike '%authentication%'  then 'auth_bypass'
            when summary ilike '%traversal%'
              or summary ilike '%path%'            then 'path_traversal'
            else                                        'other'
        end as vulnerability_category

    from bucketed

),

final as (

    select
        *,
        -- coalesce handles advisories with no published CVSS score (treated as 0)
        round(coalesce(cvss_score, 0.0) * age_risk_multiplier, 2) as composite_risk_score

    from enriched

)

select * from final
