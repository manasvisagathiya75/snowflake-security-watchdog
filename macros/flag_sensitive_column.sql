{% macro flag_sensitive_column(column_name) %}
    CASE
        WHEN LOWER({{ column_name }}) ILIKE '%email%'       THEN 'PII_EMAIL'
        WHEN LOWER({{ column_name }}) ILIKE '%phone%'       THEN 'PII_PHONE'
        WHEN LOWER({{ column_name }}) ILIKE '%ssn%'         THEN 'PII_SSN'
        WHEN LOWER({{ column_name }}) ILIKE '%password%'    THEN 'CREDENTIAL'
        WHEN LOWER({{ column_name }}) ILIKE '%secret%'      THEN 'CREDENTIAL'
        WHEN LOWER({{ column_name }}) ILIKE '%address%'     THEN 'PII_ADDRESS'
        WHEN LOWER({{ column_name }}) ILIKE '%dob%'         THEN 'PII_DOB'
        WHEN LOWER({{ column_name }}) ILIKE '%birth%'       THEN 'PII_DOB'
        WHEN LOWER({{ column_name }}) ILIKE '%credit_card%' THEN 'PII_PAYMENT'
        WHEN LOWER({{ column_name }}) ILIKE '%salary%'      THEN 'PII_FINANCIAL'
        WHEN LOWER({{ column_name }}) ILIKE '%income%'      THEN 'PII_FINANCIAL'
        ELSE 'NOT_SENSITIVE'
    END
{% endmacro %}