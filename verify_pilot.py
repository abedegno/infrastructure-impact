"""Re-run fixture, artifact and snapshot checks and persist a validation receipt."""
import hashlib
import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path
from intel import connect,latest,now,VENDORS
from cohort import COHORT,coverage
from comparison import compare
from review import signals
from sync import allowed


def main():
    result=unittest.TextTestRunner(verbosity=0).run(unittest.defaultTestLoader.discover('tests'))
    if not result.wasSuccessful():raise SystemExit(1)
    for script in ('web/app.js','web/snapshot.js'):
        subprocess.run(['node','--check',script],check=True)
    subprocess.run([sys.executable,'build_pilot.py'],check=True)
    subprocess.run(['node','tests/test_snapshot.js'],check=True)
    with connect() as db:
        records=latest(db);pairs=coverage(db,records)
        assert len(pairs)==len(COHORT)*len(VENDORS)
        for r in records:
            assert allowed(r['source_url'],r['vendor']),r['source_url']
            raw=db.execute('SELECT raw FROM evidence WHERE id=?',(r['evidence_id'],)).fetchone()[0]
            assert hashlib.sha256(raw).hexdigest()==r['sha256']
            assert all(a['cve_id'] in r['cves'] for a in r['assessments'])
        for cid in COHORT:
            assert db.execute('SELECT 1 FROM vulnerabilities WHERE cve_id=?',(cid,)).fetchone(),cid
        snapshot=json.loads(Path('site/dist/snapshot.json').read_text())
        assert all(not r['notes'] and not r['metrics'] for r in snapshot['records'])
        assert not snapshot['research']['fix_candidates']
        report={'checked_at':now(),'advisories':len(records),'imported_cves':len({c for r in records for c in r['cves']}),
            'vendors_collected':sorted({r['vendor'] for r in records}),'unit_tests_passed':result.testsRun-len(result.skipped),
            'benchmark_cves':len(COHORT),'vendor_cve_pairs':len(pairs),'coverage_states':dict(Counter(p['state'] for p in pairs)),
            'automated_checks':['Python fixture and provenance tests','JS syntax','real-dataset snapshot/Python comparison parity','custom cohort isolation','CSV formula escaping','evidence hashes','official source domain allowlist','upstream dates for all benchmark CVEs'],
            'browser_checks':'See separate browser QA receipt; these are not claimed by this automated script.',
            'disclosure_signals':len(signals(db)),'verified_silent_fix_findings':0,'release_documents_collected':db.execute('SELECT COUNT(*) FROM documents').fetchone()[0],
            'scheduler':snapshot.get('collector',{}),
            'hosting':'Immutable public generations; Sites private preview requires a separate deployment.',
            'limitations':['Bounded and curated source coverage','Juniper article application shells','Empty or incomplete structured exports','Cisco NX-OS release-note HTTP 403','HPE release-history direct page lacks usable content','No independent firmware or SBOM analysis','CSAF signatures and full schema conformance not verified']}
        Path('data/validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Validated',len(records),'records and',len(pairs),'benchmark pairs; receipt in data/validation.json')


if __name__=='__main__':main()
