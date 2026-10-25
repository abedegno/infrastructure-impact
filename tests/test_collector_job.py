import tempfile
import unittest
from pathlib import Path
from intel import connect
from collector_job import execute,ensure_runs


class ScheduledCollection(unittest.TestCase):
    def test_partial_source_failure_still_builds_and_records_partial_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'db.sqlite3';seen=[]
            def build():
                db=connect(path)
                seen.append(dict(db.execute('SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 1').fetchone()))
                db.close()
            result=execute(lambda:(2,1),lambda:(1,0),lambda:None,build,path)
            self.assertEqual(result['outcome'],'partial')
            self.assertEqual(result['imported'],3)
            self.assertEqual(seen[0]['outcome'],'partial')
            self.assertTrue(seen[0]['finished_at'])

    def test_fatal_collection_failure_does_not_publish_a_fresh_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'db.sqlite3';built=[]
            def fail():raise RuntimeError('Collection transport unavailable')
            with self.assertRaises(RuntimeError):execute(fail,lambda:(0,0),lambda:None,lambda:built.append(True),path)
            self.assertEqual(built,[])
            db=connect(path);row=db.execute('SELECT * FROM pipeline_runs').fetchone()
            self.assertEqual(row['outcome'],'error');self.assertIn('transport',row['details']);db.close()

    def test_interrupted_previous_process_cannot_appear_successful(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'db.sqlite3';db=connect(path);ensure_runs(db)
            db.execute("INSERT INTO pipeline_runs(started_at,outcome) VALUES('2026-10-25','running')");db.commit();db.close()
            execute(lambda:(0,0),lambda:(0,0),lambda:None,lambda:None,path)
            db=connect(path);rows=list(db.execute('SELECT * FROM pipeline_runs ORDER BY id'))
            self.assertEqual([r['outcome'] for r in rows],['interrupted','ok']);db.close()

    def test_snapshot_build_failure_is_recorded_as_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'db.sqlite3'
            def fail():raise OSError('Disk unavailable')
            with self.assertRaises(OSError):execute(lambda:(0,0),lambda:(0,0),lambda:None,fail,path)
            db=connect(path);self.assertEqual(db.execute('SELECT outcome FROM pipeline_runs').fetchone()[0],'error');db.close()


if __name__=='__main__':unittest.main()
