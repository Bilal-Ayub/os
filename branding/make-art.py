"""Generate the Escrow OS logo (original artwork, no third-party marks).

    python branding/make-art.py        (needs Pillow)

Writes branding/art/escrow-os.png (256x256). The motif is the overlay idea itself:
a translucent "upper" sheet lying over a "lower" page, offset, with a tick (commit)
where the two meet. The desktop wallpaper (branding/art/escrow-wallpaper.jpg) is
supplied artwork; `python branding/make-art.py --wallpaper` writes the older
generated one to branding/art/escrow-wallpaper-generated.png.
"""
import os
from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "art")
NAVY = (14, 22, 38)
NAVY2 = (24, 38, 64)
TEAL = (64, 196, 180)
AMBER = (240, 176, 72)
PAPER = (226, 232, 240)


def font(size, bold=False):
    names = ["segoeuib.ttf" if bold else "segoeui.ttf", "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"]
    for n in names:
        for d in ("C:/Windows/Fonts", "/usr/share/fonts/truetype/dejavu"):
            p = os.path.join(d, n)
            if os.path.exists(p):
                return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def emblem(size):
    """Two offset rounded layers + a tick, on a transparent background."""
    s = size
    im = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    r = s // 9
    w = int(s * 0.58)
    # lower layer: the real files
    d.rounded_rectangle([s * 0.10, s * 0.30, s * 0.10 + w, s * 0.30 + w], r, fill=PAPER + (255,))
    # upper layer: the agent's staged changes (translucent)
    up = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(up).rounded_rectangle([s * 0.32, s * 0.10, s * 0.32 + w, s * 0.10 + w], r,
                                         fill=TEAL + (200,), outline=TEAL + (255,), width=max(2, s // 64))
    im = Image.alpha_composite(im, up)
    d = ImageDraw.Draw(im)
    lw = max(3, s // 18)
    d.line([(s * 0.38, s * 0.62), (s * 0.50, s * 0.74), (s * 0.76, s * 0.44)], fill=AMBER + (255,), width=lw, joint="curve")
    return im


def wallpaper(W=1920, H=1080):
    im = Image.new("RGB", (W, H), NAVY)
    # vertical gradient
    g = Image.linear_gradient("L").resize((W, H))
    im = Image.composite(Image.new("RGB", (W, H), NAVY2), im, g.point(lambda v: 255 - v))
    d = ImageDraw.Draw(im, "RGBA")
    # faint grid of "layers"
    for x in range(0, W, 64):
        d.line([(x, 0), (x, H)], fill=(255, 255, 255, 10))
    for y in range(0, H, 64):
        d.line([(0, y), (W, y)], fill=(255, 255, 255, 10))
    # large soft offset sheets on the right
    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.rounded_rectangle([1380, 330, 1800, 750], 56, fill=PAPER + (28,))
    gd.rounded_rectangle([1470, 240, 1890, 660], 56, fill=TEAL + (46,), outline=TEAL + (120,), width=4)
    glow = glow.filter(ImageFilter.GaussianBlur(1))
    im = Image.alpha_composite(im.convert("RGBA"), glow)
    em = emblem(220)
    im.alpha_composite(em, (150, 380))
    d = ImageDraw.Draw(im)
    d.text((410, 410), "Escrow OS", font=font(120, True), fill=(240, 244, 248))
    d.text((416, 560), "Every AI agent action is a reversible transaction.", font=font(40), fill=TEAL)
    d.text((416, 616), "review  \u2192  commit  or  discard", font=font(32), fill=(170, 182, 200))
    d.text((W - 620, H - 60), "Based on Ubuntu. Not affiliated with Canonical.", font=font(22), fill=(120, 132, 150))
    return im.convert("RGB")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    import sys
    if "--wallpaper" in sys.argv:
        wallpaper().save(os.path.join(OUT, "escrow-wallpaper-generated.png"), optimize=True)
    emblem(256).save(os.path.join(OUT, "escrow-os.png"), optimize=True)
    print("wrote", os.listdir(OUT))
