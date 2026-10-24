"""Put the source of a bundled AGPL tool into code/licenses.

EVTXER passes Hayabusa and Takajo on to other teams, so their source travels
with them (AGPLv3 section 6). This is GitHub's archive of the release tag
minus images, the docs website and the upstream test fixtures - nothing a
build needs, and a release copy carries no event-log samples.

    python tools/dev/fetch_sources.py hayabusa 4.2.0
    python tools/dev/fetch_sources.py takajo 2.16.1

After an upgrade: delete the old zip and update code/licenses/NOTICE.txt.
"""
import io
import os
import re
import sys
import urllib.request
import zipfile

SKIP = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|mp4|evtx)$|/(website|screenshots|test_files)/|/tests/data/", re.I)

name, ver = sys.argv[1], sys.argv[2]
url = f"https://github.com/Yamato-Security/{name}/archive/refs/tags/v{ver}.zip"
src = zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(url).read()))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "code", "licenses",
                   f"{name}-{ver}-source.zip")
with zipfile.ZipFile(out, "w") as z:
    for i in src.infolist():
        if not SKIP.search(i.filename):
            z.writestr(i, src.read(i.filename))
print(os.path.normpath(out))
