import json
import shutil
import unittest
from pathlib import Path
from adapters import auto,checkpoint_records
from cohort import coverage,COHORT
from intel import connect,ingest,latest,VENDORS
from review import signals
from sync import discovery

FIX=Path(__file__).parent/'fixtures'
CP='https://iapi-services-ucs.checkpoint.com/public/api/support-center-mms/api/securityAdvisories/getAllActive'


class ExpandedSources(unittest.TestCase):
    def test_checkpoint_product_index_unknown_is_not_unaffected(self):
        records=checkpoint_records((FIX/'checkpoint-advisories.json').read_bytes(),CP)
        reg=[r for r in records if 'CVE-2024-6387' in r['cves']]
        self.assertTrue(reg)
        aa=[a for r in reg for a in r['assessments']]
        detail=[a for a in aa if a['versions'][0]['expression']=='Details in SK']
        self.assertTrue(detail)
        self.assertTrue(all(a['status']=='unknown' for a in detail))
        self.assertTrue(all(not a['remediations'] for a in aa))
        self.assertTrue(any(a['status']=='unaffected' for r in records for a in r['assessments']))

    def test_protection_feed_is_not_product_evidence(self):
        with self.assertRaises(ValueError):
            checkpoint_records(b'[]','https://advisories.checkpoint.com/defense/advisories/public/ips.xml')

    def test_empty_fortinet_csaf_only_proves_advisory_discovery(self):
        r=auto((FIX/'fortinet-php.json').read_bytes(),'https://filestore.fortinet.com/a.json','fortinet')
        self.assertEqual(r['cves'],['CVE-2026-109618','CVE-2026-109619'])
        self.assertEqual(r['assessments'],[])
        self.assertTrue(r['warnings'])

    def test_rss_prefers_fortinet_structured_link(self):
        raw=b'<rss xmlns:csaf="https://fortiguard.fortinet.com/rss/ns/csaf"><channel><item><link>https://www.fortiguard.com/a</link><csaf:link>https://filestore.fortinet.com/a.json</csaf:link></item></channel></rss>'
        self.assertEqual(discovery(raw,'https://x.test','rss',1),['https://filestore.fortinet.com/a.json'])

    def test_hpe_reported_date_is_not_verified_release(self):
        db=connect(':memory:')
        ingest(db,(FIX/'hpe-cray.html').read_bytes(),'https://support.hpe.com/cray',auto,'hpe')
        r=latest(db)[0]
        self.assertEqual(r['reported_fix_date'],'2024-08-28')
        self.assertEqual(len(r['assessments']),7)
        ss=signals(db)
        self.assertEqual(ss[0]['kind'],'reported_firmware_date_predates_bulletin')
        self.assertEqual(ss[0]['confidence'],'unverified_release_date_candidate')
        self.assertFalse(list(db.execute("SELECT * FROM fix_evidence WHERE review_status='verified'")))
        db.close()

    def test_hpe_curl_preserves_shared_scope_and_spr(self):
        r=auto((FIX/'hpe-document.raw').read_bytes(),'https://support.hpe.com/nonstop','hpe')
        self.assertEqual(len(r['assessments']),2)
        self.assertTrue(all(a['scope']=='bulletin_shared' for a in r['assessments']))
        self.assertIn('T1204L01^AAI',r['assessments'][0]['versions'][0]['expression'])

    def test_release_notes_exclude_other_platforms_and_conditional_nonexposure(self):
        r=auto((FIX/'fortinac-release.html').read_bytes(),'https://docs.fortinet.com/document/fortinac-f/7.4.1/release-notes/112589/common-vulnerabilities-and-exposures','fortinet')
        self.assertIn('CVE-2024-6387',r['cves'])
        self.assertNotIn('CVE-2025-32728',r['cves'])
        self.assertTrue(all(a['status']=='fixed' and 'FortiNAC-OS' in a['product'] for a in r['assessments']))
        self.assertIsNone(r['published_at'])

    @unittest.skipUnless(shutil.which('pdftotext'),'PDF attachment parsing requires Poppler')
    def test_juniper_pdf_does_not_infer_other_cve_or_release_date(self):
        r=auto((FIX/'juniper-ssr.pdf').read_bytes(),'https://supportportal.juniper.net/attachment','juniper')
        self.assertEqual(r['cves'],['CVE-2023-48795'])
        self.assertEqual(r['assessments'][0]['scope'],'bulletin_shared')
        self.assertIsNone(r['published_at'])

    @unittest.skipUnless(Path('/opt/homebrew/bin/pdftotext').is_file() or Path('/usr/local/bin/pdftotext').is_file(),'Homebrew Poppler not installed')
    def test_pdf_collection_works_with_launchd_minimal_path(self):
        from unittest.mock import patch
        with patch('shutil.which',return_value=None):
            r=auto((FIX/'juniper-ssr.pdf').read_bytes(),'https://supportportal.juniper.net/attachment','juniper')
        self.assertEqual(r['cves'],['CVE-2023-48795'])

    def test_arista_subheading_unaffected_does_not_swallow_product_list(self):
        r=auto((FIX/'arista-openssl.html').read_bytes(),'https://www.arista.com/0081','arista')
        self.assertEqual(len(r['assessments']),22)
        self.assertEqual({a['status'] for a in r['assessments']},{'unaffected'})

    def test_arista_two_cves_do_not_share_release_ranges(self):
        r=auto((FIX/'arista-openssh.html').read_bytes(),'https://www.arista.com/0100','arista')
        reg=[a for a in r['assessments'] if a['cve_id']=='CVE-2024-6387' and a['status']=='affected']
        self.assertEqual(len(reg),3)
        self.assertNotIn('4.34.0F',json.dumps(reg))
        self.assertTrue(any(a['status']=='unaffected' for a in r['assessments']))

    def test_pan_fix_table_scopes_each_cve(self):
        r=auto((FIX/'pan-oss.html').read_bytes(),'https://security.paloaltonetworks.com/PAN-SA-2025-0012','paloalto')
        a=next(a for a in r['assessments'] if a['cve_id']=='CVE-2024-1086')
        b=next(a for a in r['assessments'] if a['cve_id']=='CVE-2023-38546')
        self.assertIn('10.2.11',a['versions'][0]['expression'])
        self.assertNotIn('10.2.11',b['versions'][0]['expression'])
        self.assertEqual(a['status'],'fixed')

    def test_mixed_cna_version_dispositions_remain_separate(self):
        doc={'cveMetadata':{'cveId':'CVE-2024-6387','state':'PUBLISHED'},'containers':{'cna':{'affected':[{'product':'Router OS','versions':[{'version':'1.0','status':'affected'},{'version':'2.0','status':'unaffected'}]}]}}}
        r=auto(json.dumps(doc),'https://example.test','paloalto')
        self.assertEqual({a['status'] for a in r['assessments']},{'affected','unaffected'})
        self.assertEqual(len({a['product_id'] for a in r['assessments']}),2)
        self.assertTrue(all(len(a['versions'])==1 for a in r['assessments']))

    def test_cisco_explicit_single_cve_scope_overrides_background_mentions(self):
        r=auto((FIX/'cisco-curl.html').read_bytes(),'https://sec.cloudapps.cisco.com/curl','cisco')
        self.assertEqual(r['cves'],['CVE-2023-38545'])
        self.assertTrue(r['assessments'])
        self.assertEqual({a['cve_id'] for a in r['assessments']},{'CVE-2023-38545'})

    def test_fortinet_fixed_release_table_does_not_infer_earlier_ranges(self):
        r=auto((FIX/'fortiproxy-728.html').read_bytes(),'https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/534553/resolved-issues','fortinet')
        self.assertTrue({'CVE-2023-38545','CVE-2023-38546'}<=set(r['cves']))
        self.assertTrue(all(a['status']=='fixed' and a['versions']==[{'version':'7.2.8','status':'fixed'}] for a in r['assessments']))
        self.assertIsNone(r['published_at'])

    def test_fortinet_other_release_tables_cannot_inherit_cve_section(self):
        html=b'<h2>Common Vulnerabilities and Exposures</h2><p>FortiProxy 7.2.8 is no longer vulnerable</p><table><tr><td>1</td><td>CVE-2023-38545</td></tr></table><h2>Known issues</h2><table><tr><td>2</td><td>CVE-2023-38546</td></tr></table>'
        r=auto(html,'https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/a','fortinet')
        self.assertEqual(r['cves'],['CVE-2023-38545'])

    def test_conditional_pan_impact_retains_dependency_and_configuration_rationale(self):
        r=auto((FIX/'pan-impact-2024.html').read_bytes(),'https://security.paloaltonetworks.com/PAN-SA-2024-0001','paloalto')
        self.assertEqual(r['cves'],['CVE-2022-0847'])
        a=r['assessments'][0]
        self.assertEqual(a['status'],'unaffected')
        self.assertIn('shell access',a['exposure'][0]['details'])
        self.assertTrue(any('dependency' in w for w in r['warnings']))

    def test_checkpoint_sk_retains_product_exceptions_and_exact_build(self):
        r=auto((FIX/'checkpoint-regresshion.html').read_bytes(),'https://support.checkpoint.com/results/sk/sk182459','checkpoint')
        self.assertEqual(r['cves'],['CVE-2024-6387'])
        self.assertNotIn('CVE-2006-5051',r['cves'])
        self.assertNotIn('CVE-2024-24919',r['cves'])
        a=next(a for a in r['assessments'] if a['status']=='affected')
        self.assertIn('996002993',a['remediations'][0]['details'])
        self.assertEqual(sum(a['status']=='unaffected' for a in r['assessments']),2)
        self.assertEqual(r['published_at'],'2024-07-14')

    def test_checkpoint_terrapin_fix_does_not_imply_all_older_releases_affected(self):
        r=auto((FIX/'checkpoint-terrapin.html').read_bytes(),'https://support.checkpoint.com/results/sk/sk181833','checkpoint')
        self.assertEqual({a['status'] for a in r['assessments']},{'fixed'})
        self.assertEqual(r['assessments'][0]['versions'],[{'version':'R82','status':'fixed'}])
        self.assertIsNone(r['published_at'])

    def test_checkpoint_index_refresh_preserves_richer_sk_assessment(self):
        from unittest.mock import patch
        import tempfile
        from sync import run
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'test.sqlite3';db=connect(path)
            ingest(db,(FIX/'checkpoint-regresshion.html').read_bytes(),'https://support.checkpoint.com/results/sk/sk182459',auto,'checkpoint');db.close()
            raw=(FIX/'checkpoint-advisories.json').read_bytes()
            config={'vendors':[{'vendor':'checkpoint','kind':'checkpoint','url':CP}], 'pinned':[]}
            with patch('sync.fetch',return_value=raw):run(config,limit=200,db_path=path)
            db=connect(path);r=next(r for r in latest(db) if r['advisory_id']=='sk182459')
            self.assertEqual(r['source_format'],'Public SK article embedded JSON')
            self.assertEqual(db.execute("SELECT COUNT(*) FROM revisions WHERE advisory_id='sk182459'").fetchone()[0],1)
            db.close()

    def test_current_arista_php_keeps_fixed_cloud_services_and_current_unaffected_statement(self):
        r=auto((FIX/'arista-0200.html').read_bytes(),'https://www.arista.com/en/support/advisories-notices/security-advisory/24846-security-advisory-0200','arista')
        self.assertEqual(r['cves'],['CVE-2026-109618','CVE-2026-109619'])
        self.assertEqual(r['published_at'],'2026-10-23')
        self.assertEqual(sum(a['status']=='fixed' for a in r['assessments']),4)
        self.assertEqual(sum(a['status']=='unaffected' for a in r['assessments']),2)
        self.assertEqual({a['scope'] for a in r['assessments']},{'bulletin_shared'})
        self.assertFalse(any(a['status']=='affected' for a in r['assessments']))
        self.assertTrue(all('cloud' in a['product'].lower() or 'Threat Management' in a['product'] for a in r['assessments'] if a['status']=='fixed'))

    def test_current_arista_div_headings_bind_ranges_to_correct_product(self):
        r=auto((FIX/'arista-0201.html').read_bytes(),'https://www.arista.com/en/support/advisories-notices/security-advisory/24847-security-advisory-0201','arista')
        eos=next(a for a in r['assessments'] if a['product'].startswith('EOS '))
        agent=next(a for a in r['assessments'] if a['product'].startswith('Streaming Telemetry Agent'))
        self.assertIn('4.36.3M',json.dumps(eos['versions']))
        self.assertNotIn('v1.46.2',json.dumps(eos['versions']))
        self.assertIn('v1.46.2',json.dumps(agent['versions']))
        self.assertEqual(r['cves'],['CVE-2026-111943'])

    def test_missing_index_match_does_not_become_unaffected(self):
        db=connect(':memory:');coverage(db,[],[])
        db.execute('INSERT INTO coverage_checks VALUES(?,?,?,?,?,?,?)',('checkpoint','CVE-2024-6387','2026-10-25','https://example.test','current feed only','no_match',None))
        pairs=coverage(db,[],['CVE-2024-6387'])
        self.assertEqual(len(pairs),len(VENDORS))
        cp=next(p for p in pairs if p['vendor']=='checkpoint')
        self.assertEqual(cp['state'],'index_checked_no_match')
        self.assertFalse(cp['advisory_sources'])
        self.assertEqual(len(COHORT),24)
        db.close()


if __name__=='__main__': unittest.main()
