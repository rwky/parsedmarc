-- Sample SQLite queries for parsedmarc aggregate data
-- Replace :start_ts and :end_ts with ISO timestamps (or adjust filters as needed)

-- 1. DMARC alignment counts between a timeframe (grouped by policy domain)
WITH per_record AS (
    SELECT
        json_extract(agg.report_json, '$.policy_published.domain') AS domain,
        json_extract(record.value, '$.alignment.dmarc') AS dmarc_aligned
    FROM dmarc_aggregate AS agg,
         json_each(agg.report_json, '$.records') AS record
    WHERE agg.inserted_at BETWEEN :start_ts AND :end_ts
)
SELECT
    domain,
    CASE dmarc_aligned WHEN 1 THEN 'pass' ELSE 'fail' END AS dmarc_result,
    COUNT(*) AS record_count
FROM per_record
GROUP BY domain, dmarc_result
ORDER BY domain, dmarc_result;

-- 2. DKIM alignment counts
WITH per_record AS (
    SELECT
        json_extract(agg.report_json, '$.policy_published.domain') AS domain,
        json_extract(record.value, '$.alignment.dkim') AS dkim_aligned
    FROM dmarc_aggregate AS agg,
         json_each(agg.report_json, '$.records') AS record
    WHERE agg.inserted_at BETWEEN :start_ts AND :end_ts
)
SELECT
    domain,
    CASE dkim_aligned WHEN 1 THEN 'pass' ELSE 'fail' END AS dkim_result,
    COUNT(*) AS record_count
FROM per_record
GROUP BY domain, dkim_result
ORDER BY domain, dkim_result;

-- 3. SPF alignment counts
WITH per_record AS (
    SELECT
        json_extract(agg.report_json, '$.policy_published.domain') AS domain,
        json_extract(record.value, '$.alignment.spf') AS spf_aligned
    FROM dmarc_aggregate AS agg,
         json_each(agg.report_json, '$.records') AS record
    WHERE agg.inserted_at BETWEEN :start_ts AND :end_ts
)
SELECT
    domain,
    CASE spf_aligned WHEN 1 THEN 'pass' ELSE 'fail' END AS spf_result,
    COUNT(*) AS record_count
FROM per_record
GROUP BY domain, spf_result
ORDER BY domain, spf_result;

-- 4. Rows where DMARC alignment failed
SELECT
    agg.id,
    agg.report_id,
    json_extract(agg.report_json, '$.policy_published.domain') AS domain,
    json_extract(record.value, '$.source.ip_address') AS source_ip,
    json_extract(record.value, '$.alignment.dmarc') AS dmarc_aligned,
    json_extract(record.value, '$.policy_evaluated.disposition') AS disposition,
    agg.inserted_at
FROM dmarc_aggregate AS agg,
     json_each(agg.report_json, '$.records') AS record
WHERE json_extract(record.value, '$.alignment.dmarc') = 0
ORDER BY agg.inserted_at DESC;

-- 5. DMARC pass/fail percentage over a timeframe
WITH per_record AS (
    SELECT
        json_extract(agg.report_json, '$.policy_published.domain') AS domain,
        json_extract(record.value, '$.alignment.dmarc') AS dmarc_aligned
    FROM dmarc_aggregate AS agg,
         json_each(agg.report_json, '$.records') AS record
    WHERE agg.inserted_at BETWEEN :start_ts AND :end_ts
),
counts AS (
    SELECT domain, dmarc_aligned, COUNT(*) AS record_count
    FROM per_record
    GROUP BY domain, dmarc_aligned
),
totals AS (
    SELECT domain, SUM(record_count) AS total_records
    FROM counts
    GROUP BY domain
)
SELECT
    counts.domain,
    CASE dmarc_aligned WHEN 1 THEN 'pass' ELSE 'fail' END AS dmarc_result,
    record_count,
    ROUND(record_count * 100.0 / totals.total_records, 2) AS percent_of_total
FROM counts
JOIN totals ON totals.domain = counts.domain
ORDER BY counts.domain, dmarc_result;
