import copy
import json
import unittest
from contextlib import closing
from pathlib import Path

from adapters import auto, availability, csaf
from comparison import advisory_delays, compare
from intel import connect, evidence, history, ingest, latest
from review import add_fix_evidence, import_release_note, signals
from server import state
from sync import allowed, discovery

FIXTURES = Path(__file__).parent/'fixtures'


def fixture(name, vendor):
    return auto((FIXTURES/name).read_bytes(), 'https://example.test/'+name, vendor)


def document():
    return {'document': {'title':'Example','tracking':{'id':'EX-1','status':'final','initial_release_date':'2025-02-01T00:00:00Z'}},
            'product_tree': {'full_product_names':[{'product_id':'router','name':'Router 1.0'},{'product_id':'switch','name':'Switch 2.0'}],
                             'product_groups':[{'group_id':'routers','product_ids':['router']}]},
            'vulnerabilities':[{'cve':'CVE-2025-12345','product_status':{'known_affected':['router'],'known_not_affected':['switch']},
                                'remediations':[{'category':'vendor_fix','details':'Version 1.1 (ETA: TBD)','group_ids':['routers']}]},
                               {'cve':'CVE-2025-54321','product_status':{'under_investigation':['switch']}}]}


class VendorFixtures(unittest.TestCase):
    def test_cisco_investigation_unaffected_and_planned_product_fixes(self):
        d=fixture('cisco-php.html','cisco')
        a=d['assessments']
        self.assertTrue(any('Catalyst Center' in x['product'] and x['status']=='investigating' for x in a))
        self.assertTrue(any(x['product']=='IOS XE Software' and x['status']=='unaffected' for x in a))
        affected=[x for x in a if 'Ultra-Reliable' in x['product']]
        self.assertEqual(affected[0]['remediations'][0]['availability'],'planned')
        self.assertEqual(d['published_at'],'2026-10-21T19:12:00Z')

    def test_arista_product_role_and_cve_boundaries(self):
        d=fixture('arista-log4shell.html','arista')
        self.assertTrue(any(x['product']=='CloudVision Portal' and x['cve_id']=='CVE-2021-44228' and x['status']=='affected' for x in d['assessments']))
        self.assertTrue(any(x['product']=='Arista EOS-based products' and x['status']=='unaffected' for x in d['assessments']))
        self.assertFalse(any(x['product']=='Applies to deployments with' for x in d['assessments']))
        self.assertFalse(any(x['product']=='CloudVision Portal' and x['cve_id']=='CVE-2021-4104' and x['status']=='affected' for x in d['assessments']))
        self.assertEqual(d['published_at'],'2021-12-12')

    def test_arista_csaf_retains_installed_platform_relationships_and_draft(self):
        d=fixture('arista120.json','arista')
        self.assertEqual(d['document_status'],'draft')
        self.assertEqual(len(d['assessments']),3)
        self.assertTrue(any('source document' in w.lower() for w in d['warnings']))
        self.assertTrue(any(x['product_context'] for x in d['assessments']))

    def test_aruba_partial_mitigation_is_not_a_complete_fix(self):
        d=fixture('aruba.json','aruba')
        claims=[a for a in d['assessments'] if a['product_id']=='CPPM-6.14.1']
        self.assertEqual(claims[0]['source_statuses'],['fixed'])
        self.assertEqual(claims[0]['status'],'partially_mitigated')
        self.assertEqual(claims[0]['remediations'][0]['availability'],'partial_mitigation')

    def test_missing_cna_versions_remains_unknown(self):
        raw={'cveMetadata':{'cveId':'CVE-2025-12345'},'containers':{'cna':{'title':'Example','affected':[{'product':'Box','vendor':'Example','defaultStatus':'unaffected'}]}}}
        self.assertEqual(auto(json.dumps(raw),'https://example.test','arista')['assessments'][0]['status'],'unknown')


class CSAFScopes(unittest.TestCase):
    def test_cve_and_group_remediations_stay_scoped(self):
        d=csaf(json.dumps(document()),'https://example.test','arista')
        a={ (a['cve_id'],a['product_id']):a for a in d['assessments']}
        self.assertNotIn(('CVE-2025-54321','router'),a)
        self.assertEqual(a[('CVE-2025-12345','switch')]['remediations'],[])
        self.assertEqual(a[('CVE-2025-12345','router')]['remediations'][0]['availability'],'planned')

    def test_incompatible_statuses_are_visible(self):
        d=document();d['vulnerabilities'][0]['product_status']['fixed']=['router']
        out=csaf(json.dumps(d),'https://example.test','arista')
        self.assertEqual(next(a for a in out['assessments'] if a['product_id']=='router')['status'],'conflicting')

    def test_fix_category_without_release_evidence_is_not_verified_released(self):
        self.assertEqual(availability('Fixed in 1.2','vendor_fix'),'vendor_reports_fixed')
        self.assertEqual(availability('Fixed in 1.2','vendor_fix','2099-01-01T00:00:00Z'),'planned')


class RevisionTests(unittest.TestCase):
    def test_idempotence_and_source_reversion(self):
        with closing(connect(':memory:')) as db:
            a=json.dumps(document());changed=document();changed['vulnerabilities'][0]['product_status']['known_affected']=[];b=json.dumps(changed)
            self.assertTrue(ingest(db,a,'https://example.test',auto,'arista'))
            self.assertFalse(ingest(db,a,'https://example.test',auto,'arista'))
            ingest(db,b,'https://example.test',auto,'arista');ingest(db,a,'https://example.test',auto,'arista')
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],3)
            self.assertEqual(len(history(db)),2)

    def test_csaf_tuples_do_not_create_false_revisions(self):
        raw=(FIXTURES/'arista120.json').read_bytes()
        with closing(connect(':memory:')) as db:
            ingest(db,raw,'https://example.test',auto,'arista')
            self.assertFalse(ingest(db,raw,'https://example.test',auto,'arista'))

    def test_parser_corrections_do_not_become_vendor_disclosure_signals(self):
        raw=json.dumps(document())
        def parser1(raw,url,vendor):
            d=auto(raw,url,vendor);d['cves']=d['cves'][:1];d['assessments']=[a for a in d['assessments'] if a['cve_id'] in d['cves']];return d
        with closing(connect(':memory:')) as db:
            ingest(db,raw,'https://example.test',parser1,'arista');ingest(db,raw,'https://example.test',auto,'arista')
            self.assertEqual(history(db)[0]['kind'],'parser_reinterpretation')
            self.assertFalse(signals(db))

    def test_vendor_advisory_identity_prevents_unrelated_overwrite(self):
        with closing(connect(':memory:')) as db:
            a=document();b=copy.deepcopy(a);b['document']['tracking']['id']='EX-2'
            ingest(db,json.dumps(a),'https://example.test/a',auto,'arista');ingest(db,json.dumps(b),'https://example.test/b',auto,'arista')
            self.assertEqual(len(latest(db)),2)


class Comparisons(unittest.TestCase):
    def test_counts_are_distinct_cves_with_explicit_coverage_denominators(self):
        r=csaf(json.dumps(document()),'https://example.test','arista')
        result=compare([r,r],['CVE-2025-12345','CVE-2025-54321','CVE-2025-99999'])
        row=next(v for v in result['vendors'] if v['vendor']=='arista')
        self.assertEqual((row['affected_cves'],row['assessed_cves'],row['cohort_size']),(1,2,3))
        self.assertEqual(row['no_assessment_in_dataset'],1)
        self.assertEqual(row['unaffected_cves'],1)
        missing=next(v for v in result['vendors'] if v['vendor']=='juniper')
        self.assertEqual(missing['no_assessment_in_dataset'],3)

    def test_draft_claims_are_excluded_and_disclosed(self):
        result=compare([fixture('arista120.json','arista')])
        self.assertEqual(result['draft_advisories_excluded'],1)
        self.assertEqual(next(v for v in result['vendors'] if v['vendor']=='arista')['affected_cves'],0)

    def test_delay_is_named_as_sample_observation_not_notification_time(self):
        r=csaf(json.dumps(document()),'https://example.test','arista')
        result=advisory_delays([r],{'CVE-2025-12345':{'published_at':'2025-01-01T00:00:00Z','source_url':'https://upstream.test'}})
        self.assertEqual(result[0]['days'],31)
        self.assertIn('not proof',result[0]['meaning'])


class DisclosureResearch(unittest.TestCase):
    def test_security_language_without_cve_is_only_a_review_candidate(self):
        with closing(connect(':memory:')) as db:
            import_release_note(db,b'<h1>Router 1.1</h1><p>Security update improves authentication.</p>','https://example.test/release','arista','Router')
            s=signals(db)
            self.assertEqual(s[0]['kind'],'security_change_without_cve_reference')
            self.assertEqual(s[0]['confidence'],'review_required')
            self.assertNotIn('cve_id',s[0])

    def test_release_document_with_cve_does_not_trigger_no_cve_signal(self):
        with closing(connect(':memory:')) as db:
            import_release_note(db,b'<p>Security fix for CVE-2025-12345.</p>','https://example.test/release','arista','Router')
            self.assertEqual(signals(db),[])

    def test_fix_before_advisory_requires_reviewed_release_and_link_evidence(self):
        with closing(connect(':memory:')) as db:
            ingest(db,json.dumps(document()),'https://example.test/advisory',auto,'arista')
            release=evidence(db,b'release evidence','https://example.test/release')['id']
            link=evidence(db,b'product version CVE linkage','https://example.test/link')['id']
            add_fix_evidence(db,'arista','Router 1.0','CVE-2025-12345','1.1','2025-01-01',release,link,'Vendor confirms the specific product/version fix.')
            self.assertFalse(signals(db))
            db.execute("UPDATE fix_evidence SET review_status='verified'")
            signal=signals(db)[0]
            self.assertEqual(signal['kind'],'fix_predates_collected_advisory')
            self.assertIn('intent is not established',signal['explanation'])

    def test_new_cve_source_revision_signal_keeps_earlier_disclosure_uncertainty(self):
        with closing(connect(':memory:')) as db:
            a=document();a['vulnerabilities']=a['vulnerabilities'][:1]
            ingest(db,json.dumps(a),'https://example.test',auto,'arista')
            ingest(db,json.dumps(document()),'https://example.test',auto,'arista')
            self.assertTrue(any(s['kind']=='cve_reference_added' for s in signals(db)))

    def test_missing_evidence_rejects_fix_candidate(self):
        with closing(connect(':memory:')) as db:
            with self.assertRaises(ValueError):
                add_fix_evidence(db,'arista','Router','CVE-2025-12345','1.1','2025-01-01',100,200,'Unverified assertion')


class CollectionAndAPI(unittest.TestCase):
    def test_feed_order_and_vendor_domain_constraints(self):
        raw=b'2025/old.json\n2026/new.json'
        self.assertEqual(discovery(raw,'https://example.test/index.txt','index',1),['https://example.test/2026/new.json'])
        self.assertEqual(discovery(raw,'https://example.test/index.txt','index',1,'newest_first'),['https://example.test/2025/old.json'])
        self.assertFalse(allowed('https://cisco.com.evil.test/source','cisco'))
        self.assertFalse(allowed('http://127.0.0.1/source','cisco'))
        self.assertTrue(allowed('https://sec.cloudapps.cisco.com/source','cisco'))

    def test_empty_database_api_state_has_no_fabricated_findings(self):
        with closing(connect(':memory:')) as db:
            s=state(db,['CVE-2025-12345'])
            self.assertEqual(s['records'],[])
            self.assertEqual(s['signals'],[])
            self.assertEqual(s['comparison']['vendors'][0]['no_assessment_in_dataset'],1)


if __name__=='__main__':
    unittest.main()
