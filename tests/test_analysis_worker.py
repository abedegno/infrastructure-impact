"""The opt-in reader binds a real classic worker to its immutable page assets."""

import re
import shutil
import subprocess
from hashlib import sha256

import pytest
from test_analysis_precomputed import numeric_source, public_projection

from infrastructure_impact.application import analysis_precomputed as precomputed
from infrastructure_impact.application import publication, publication_v2


@pytest.mark.parametrize("base", ["/", "/nested/evidence/"])
def test_worker_asset_binding(tmp_path, monkeypatch, base):
    monkeypatch.setenv("IMPACT_BASE_PATH", base)
    publication.write_reader_assets(
        tmp_path,
        {"generated_at": "2025-01-01"},
        publication_format="v2",
        analysis_precomputed_delivery=True,
    )
    html = (tmp_path / "index.html").read_text()
    tag = re.search(r"<script [^>]*data-analysis-worker=[^>]+>", html)
    assert tag, "Preview must bind the worker in its immutable client script tag"
    client = (tmp_path / "analysis-worker-client.js").read_bytes()
    assert f'src="{base}assets/{sha256(client).hexdigest()}.js"' in tag[0]
    name = re.search(r'data-analysis-worker="([a-f0-9]{64}\.js)"', tag[0])[1]
    bundle = tmp_path / "assets" / name
    assert sha256(bundle.read_bytes()).hexdigest() + ".js" == name
    if node := shutil.which("node"):
        subprocess.run([node, "--check", bundle], check=True)


def test_worker_reader_and_exports(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node unavailable")
    public = public_projection()
    publication_v2.write_bundle(
        tmp_path,
        public,
        analysis_precomputed_delivery=True,
        analysis_precomputed_options=[{"vendor": "cisco"}, {"vendor": "aruba"}],
    )
    (tmp_path / "source.json").write_bytes(precomputed.compact_bytes(public["switching_analysis"]))
    numeric = numeric_source()
    manifest = precomputed.write_views(tmp_path, numeric, [{"vendor": "arista"}])
    (tmp_path / "numeric.json").write_bytes(precomputed.compact_bytes(numeric))
    (tmp_path / "numeric-manifest.json").write_bytes(precomputed.compact_bytes(manifest))
    subprocess.run([node, "tests/test_analysis_worker.js", tmp_path], check=True, timeout=90)
