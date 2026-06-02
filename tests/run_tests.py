# Author: Mihir Brijesh Solanki (40481948)
"""Stdlib test runner — no pytest required.

Run with: python3 tests/run_tests.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

app = create_app('testing')
client = app.test_client()
db = app.extensions['cwe_db']

passed = 0
failed = 0

def check(label, condition, detail=''):
    global passed, failed
    if condition:
        print(f'  PASS  {label}')
        passed += 1
    else:
        print(f'  FAIL  {label}' + (f': {detail}' if detail else ''))
        failed += 1

# ─── Weakness by ID ───────────────────────────────────────────────
print('\n── GET /api/v1/weaknesses/<id> ──')
r = client.get('/api/v1/weaknesses/79')
check('valid CWE 79 returns 200', r.status_code == 200)
data = r.get_json()
for field in ('cwe_id','name','abstraction','description','likelihood_of_exploit','consequences','applicable_platforms','detection_methods'):
    check(f'response has field: {field}', field in data)
check('cwe_id value is 79', data.get('cwe_id') == 79)

r = client.get('/api/v1/weaknesses/99999')
check('ID>9999 returns 400', r.status_code == 400)
check('400 response is JSON', r.content_type.startswith('application/json'))

r = client.get('/api/v1/weaknesses/0')
check('ID=0 returns 400', r.status_code == 400)

r = client.get('/api/v1/weaknesses/8888')
check('nonexistent CWE returns 404', r.status_code == 404)
check('404 is JSON', r.content_type.startswith('application/json'))
body = r.get_data(as_text=True)
check('no Traceback in 404 body', 'Traceback' not in body)
check('no Exception in 404 body', 'Exception' not in body)

r = client.post('/api/v1/weaknesses/79', json={})
check('POST returns 405', r.status_code == 405)
check('405 is JSON', r.content_type.startswith('application/json'))

# Security headers
r = client.get('/api/v1/weaknesses/89')
h = r.headers
check("CSP header set", 'Content-Security-Policy' in h)
check("CSP is default-src 'self'", "default-src 'self'" in h.get('Content-Security-Policy',''))
check("X-Content-Type-Options: nosniff", h.get('X-Content-Type-Options') == 'nosniff')
check("X-Frame-Options: DENY", h.get('X-Frame-Options') == 'DENY')
check("Strict-Transport-Security present", 'Strict-Transport-Security' in h)
check("Referrer-Policy: no-referrer", h.get('Referrer-Policy') == 'no-referrer')

# ─── Search ───────────────────────────────────────────────────────
print('\n── GET /api/v1/weaknesses/search ──')
r = client.get('/api/v1/weaknesses/search')
check('default search 200', r.status_code == 200)
data = r.get_json()
check('has total', 'total' in data)
check('has results list', isinstance(data.get('results'), list))
check('default limit is 20', data.get('limit') == 20)
check('default offset is 0', data.get('offset') == 0)

r = client.get('/api/v1/weaknesses/search?likelihood=High')
check('likelihood=High 200', r.status_code == 200)
data = r.get_json()
check('all results have High likelihood', all(x['likelihood_of_exploit']=='High' for x in data['results']))

r = client.get('/api/v1/weaknesses/search?likelihood=Critical')
check('invalid likelihood rejected 400', r.status_code == 400)

r = client.get('/api/v1/weaknesses/search?abstraction=SuperClass')
check('invalid abstraction rejected 400', r.status_code == 400)

r = client.get('/api/v1/weaknesses/search?unknown=xyz')
check('unknown param rejected 400', r.status_code == 400)

r = client.get('/api/v1/weaknesses/search?limit=101')
check('limit>100 rejected 400', r.status_code == 400)

r = client.get('/api/v1/weaknesses/search?limit=-1')
check('negative limit rejected 400', r.status_code == 400)

r = client.get('/api/v1/weaknesses/search?offset=-5')
check('negative offset rejected 400', r.status_code == 400)

r = client.get('/api/v1/weaknesses/search?platform=' + 'A'*51)
check('platform>50 chars rejected 400', r.status_code == 400)

r = client.get("/api/v1/weaknesses/search?platform='; DROP TABLE weaknesses; --")
check('SQL injection attempt handled (400 or safe 200)', r.status_code in (200, 400))
count = db.execute('SELECT COUNT(*) FROM weaknesses').fetchone()[0]
check('weaknesses table intact after SQLi attempt', count == 969)

r = client.get("/api/v1/weaknesses/search?platform=' OR '1'='1")
check('short SQL injection safe', r.status_code in (200, 400))
count2 = db.execute('SELECT COUNT(*) FROM weaknesses').fetchone()[0]
check('table still intact after second SQLi', count2 == 969)

r = client.get('/api/v1/weaknesses/search?limit=3')
data = r.get_json()
check('limit=3 returns <=3 results', len(data['results']) <= 3)

r = client.get('/api/v1/weaknesses/search?platform=Java')
check('platform=Java 200', r.status_code == 200)
data = r.get_json()
for item in data['results']:
    plats = [p['name'] for p in item['applicable_platforms']]
    check('Java result actually has Java platform', any('Java' in p for p in plats))
    break

r = client.get('/api/v1/weaknesses/search?abstraction=Base&likelihood=High')
check('combined filters 200', r.status_code == 200)

# ─── Analysis ─────────────────────────────────────────────────────
print('\n── GET /api/v1/analysis/consequence-platform-matrix ──')
r = client.get('/api/v1/analysis/consequence-platform-matrix')
check('analysis 200', r.status_code == 200)
check('analysis is JSON', r.content_type.startswith('application/json'))
data = r.get_json()
check('has matrix', 'matrix' in data)
check('has top_risks', 'top_risks' in data)
check('has metadata', 'metadata' in data)

meta = data['metadata']
check('metadata.total_weaknesses > 0', meta.get('total_weaknesses_in_dataset',0) > 0)
check('metadata.total_weaknesses == 969', meta.get('total_weaknesses_in_dataset') == 969)
check('metadata.platforms_analysed is list', isinstance(meta.get('platforms_analysed'), list))

matrix = data['matrix']
check('matrix non-empty', len(matrix) > 0)
for plat, scopes in matrix.items():
    for scope, impacts in scopes.items():
        for impact, stats in impacts.items():
            check(f'{plat}/{scope}/{impact} has count int', isinstance(stats.get('count'), int))
            check(f'{plat}/{scope}/{impact} has percentage float', isinstance(stats.get('percentage'), (int,float)))
            check(f'percentage in [0,100]', 0 <= stats['percentage'] <= 100)

all_scopes = set()
for pd in matrix.values():
    all_scopes.update(pd.keys())
cia = {'Confidentiality','Integrity','Availability'}
check('CIA scopes present in matrix', len(cia & all_scopes) >= 2)

top_risks = data['top_risks']
for plat, risks in top_risks.items():
    check(f'{plat} has <=3 top risks', len(risks) <= 3)
    scopes_list = [r['distinct_consequence_scopes'] for r in risks]
    check(f'{plat} top risks sorted descending', scopes_list == sorted(scopes_list, reverse=True))
    for risk in risks:
        check(f'risk has cwe_id int', isinstance(risk.get('cwe_id'), int))
        check(f'risk has name str', isinstance(risk.get('name'), str))

r = client.post('/api/v1/analysis/consequence-platform-matrix', json={})
check('POST on analysis returns 405', r.status_code == 405)
check('405 on analysis is JSON', r.content_type.startswith('application/json'))

r = client.get('/api/v1/analysis/nonexistent')
check('unknown analysis route 404', r.status_code == 404)
check('404 on analysis is JSON', r.content_type.startswith('application/json'))

# ─── Summary ──────────────────────────────────────────────────────
print(f'\n{"="*55}')
total = passed + failed
print(f'RESULTS: {passed} passed, {failed} failed / {total} total')
print('='*55)
sys.exit(0 if failed == 0 else 1)
