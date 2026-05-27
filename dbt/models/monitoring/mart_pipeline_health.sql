{{ config(contract={"enforced": true}) }}

with source_metrics as (

    select
        'RAW_GITHUB_ADVISORIES'                                                          as source_table,
        max(INGESTED_AT)                                                                 as last_ingested_at,
        datediff('hour', max(INGESTED_AT), current_timestamp())                          as hours_since_last_load,
        count(*)                                                                         as total_rows,
        count(case when INGESTED_AT >= dateadd('hour', -24, current_timestamp()) then 1 end) as rows_last_24h,
        count(case when INGESTED_AT >= dateadd('day',  -7,  current_timestamp()) then 1 end) as rows_last_7d

    from {{ source('raw', 'RAW_GITHUB_ADVISORIES') }}

),

with_averages as (

    select
        *,
        round(rows_last_7d / 7.0, 0)::number as avg_daily_rows_7d

    from source_metrics

),

with_flags as (

    select
        *,
        case when hours_since_last_load <= 25                    then true else false end as is_fresh,
        case when rows_last_24h >= (avg_daily_rows_7d * 0.5)    then true else false end as is_row_count_normal

    from with_averages

),

final as (

    select
        source_table,
        last_ingested_at,
        hours_since_last_load,
        total_rows,
        rows_last_24h,
        rows_last_7d,
        avg_daily_rows_7d,
        is_fresh,
        is_row_count_normal,
        case
            when is_fresh     and     is_row_count_normal then 'healthy'
            when is_fresh     and not is_row_count_normal then 'low_volume_warning'
            when not is_fresh                             then 'stale'
            else                                               'unknown'
        end                  as pipeline_status,
        current_timestamp()::timestamp_tz  as checked_at

    from with_flags

)

select * from final
