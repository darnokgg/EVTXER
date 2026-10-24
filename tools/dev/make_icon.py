"""Build code/assets/app.ico, the EVTXER "Stoop" mark.

A peregrine stooping onto log lines; the red line is the detection. 16 and
24 px get a heavier, pixel-aligned drawing - the fine one blurs there.

    python tools/dev/make_icon.py code/assets/app.ico [preview.png]
"""
import sys
from PIL import Image, ImageDraw
out = sys.argv[1]
preview = sys.argv[2] if len(sys.argv) > 2 else None
K = 16                      # 64-unit design drawn at 1024 px, then scaled down
def draw_small():
    # 16 and 24 px: no inner padding, 2 px bars on whole pixels at 16 px.
    im = Image.new('RGBA', (64*K, 64*K), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([0, 0, 64*K-1, 64*K-1], radius=10*K, fill='#1E2126')
    m = lambda x, y: (x*K, y*K)
    d.polygon([m(6,6), m(32,25), m(58,6), m(58,18), m(32,37), m(6,18)], fill='#85C7F2')
    d.rectangle([*m(12,40), *m(52,48)], fill='#A8AEB8')
    d.rectangle([*m(20,52), *m(44,60)], fill='#F2A0A0')
    return im
def draw():
    im = Image.new('RGBA', (64*K, 64*K), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    # Dark tile, so the mark reads on a light or a dark taskbar.
    d.rounded_rectangle([0, 0, 64*K-1, 64*K-1], radius=12*K, fill='#1E2126')
    m = lambda x, y: ((8 + x*0.75)*K, (8 + y*0.75)*K)   # mark into the inner 48 units
    d.polygon([m(6,6), m(32,28), m(58,6), m(58,17), m(32,40), m(6,17)], fill='#85C7F2')
    d.rounded_rectangle([*m(10,46), *m(54,51)], radius=K, fill='#A8AEB8')
    d.rounded_rectangle([*m(18,55), *m(46,60)], radius=K, fill='#F2A0A0')
    return im
big = draw()
sizes = [16, 24, 32, 48, 64, 128, 256]
small = draw_small()
imgs = [(small if s <= 24 else big).resize((s, s), Image.LANCZOS) for s in sizes]
imgs[-1].save(out, format='ICO', sizes=[(s, s) for s in sizes], append_images=imgs[:-1])
if not preview:
    sys.exit(0)
# Contact sheet: every size at 1x and 16/32 enlarged, on dark and light.
sheet = Image.new('RGBA', (1000, 600), '#F3F3F3')
sheet.paste(Image.new('RGBA', (1000, 300), '#202020'), (0, 0))
for row, y in ((0, 10), (1, 310)):
    x = 10
    for im in imgs:
        sheet.alpha_composite(im, (x, y)); x += im.width + 12
    for s in (16, 32):
        z = imgs[sizes.index(s)].resize((s*4, s*4), Image.NEAREST)
        sheet.alpha_composite(z, (x, y)); x += z.width + 12
sheet.save(preview)
