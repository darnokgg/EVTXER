"""Runs one Hayabusa scan and counts detections per rule while the results file is
being written (Defender locks it once it is closed: it quotes attack command
lines). Usage: scan_count.py <exe> <evtx dir> <out jsonl> <summary json>"""
import sys, json, time, subprocess, collections, os
exe, evtx, out, summ = sys.argv[1:5]
open(out, 'w').close()                    # exists before Hayabusa writes (-C overwrites it)
f = open(out, 'r', encoding='utf-8', errors='replace')   # opened before Defender has anything to flag
p = subprocess.Popen([exe, 'dfir-timeline', '-d', evtx, '-o', out, '-t', 'JSONL', '-p', 'super-verbose',
                      '-w', '-O', '-b', '-C', '-q', '-N', '-K'], cwd=os.path.dirname(exe),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
counts = collections.Counter(); keys = set(); total = bad = 0
buf = ''
done = False
with f:
    while True:
        chunk = f.read(1 << 20)
        if not chunk and not done and p.poll() is not None:
            done = True              # it has exited: read once more for what it wrote last
            continue
        if chunk:
            buf += chunk
            *lines, buf = buf.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    bad += 1; continue
                # Titles repeat across rules - count per rule, named by title + id.
                total += 1; counts[f"{o.get('RuleTitle', '?')} [{str(o.get('RuleID', ''))[:8]}]"] += 1; keys.update(o.keys())
        elif done:
            break
        else:
            time.sleep(0.05)
if buf.strip():
    try:
        o = json.loads(buf); total += 1; counts[f"{o.get('RuleTitle', '?')} [{str(o.get('RuleID', ''))[:8]}]"] += 1; keys.update(o.keys())
    except Exception:
        bad += 1
json.dump({'total': total, 'bad': bad, 'keys': sorted(keys), 'rules': counts, 'exit': p.returncode}, open(summ, 'w'))
print(os.path.basename(exe), 'exit', p.returncode, 'detections', total, 'unparsable', bad, 'rules', len(counts))
