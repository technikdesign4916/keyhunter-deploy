-- Clean up channels injected by the auto-injector that failed the content audit:
-- 1) HTML/404 endpoints (not LLM at all) -> park
-- 2) webbrain answers 200 but serves its own model -> delete
-- 3) aitunnel needs /v1 in base_url -> fix, then re-probe
BEGIN;

UPDATE channels SET status = 2
WHERE name IN ('api-134424-04', 'xiaoai-134424-03', 'llm-134424-02');

UPDATE abilities SET enabled = false
WHERE channel_id IN (SELECT id FROM channels WHERE name IN ('api-134424-04','xiaoai-134424-03','llm-134424-02'));

DELETE FROM abilities WHERE channel_id IN (SELECT id FROM channels WHERE name = 'api-134424-01');
DELETE FROM channels WHERE name = 'api-134424-01';

UPDATE channels
SET base_url = 'https://api.aitunnel.ru/v1'
WHERE name = 'api-134424-05' AND base_url NOT LIKE '%/v1';

COMMIT;

SELECT id, name, status, substr(base_url,1,40) AS base
FROM channels
WHERE name IN ('api-134424-04','xiaoai-134424-03','llm-134424-02','api-134424-01','api-134424-05','sabbir-134424-00')
ORDER BY id;