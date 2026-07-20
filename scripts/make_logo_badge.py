"""Regenerates nuncio/web/static/nuncio-logo-badge.png from assets/nuncio-logo-full.png.

Requires Pillow (tooling only; not a runtime dependency).

Draws the source logo centered on a plain white circle (no ring), matching
the badge treatment used in the README header.
"""
from pathlib import Path

from PIL import Image, ImageDraw

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOGO = REPO_ROOT / "assets" / "nuncio-logo-full.png"
OUTPUT_BADGE = REPO_ROOT / "nuncio" / "web" / "static" / "nuncio-logo-badge.png"

# Work at 4x the final size for clean anti-aliasing, then downscale once at
# the end -- cheaper and sharper than trying to anti-alias the circle mask
# directly at 1024x1024.
SUPERSAMPLE = 4
FINAL_SIZE = 1024
CANVAS_SIZE = FINAL_SIZE * SUPERSAMPLE

# The source logo is scaled to fill this fraction of the circle's diameter,
# centered -- leaving only a hairline of white circle (~2%) around the mark, so
# the disc hugs the logo rather than floating it in a large white field.
LOGO_FRACTION_OF_CIRCLE = 0.98

# The source PNG carries a full-frame haze of near-transparent noise pixels
# (alpha 1..~32). A plain getbbox() sees that haze as "content" and returns the
# whole frame, which both defeats the crop (the real mark stays tiny inside the
# disc) and leaves visible speckle in the corners. Zero out everything below this
# alpha so the crop finds the true mark and the composite is clean.
NOISE_FLOOR = 40

WHITE = (255, 255, 255, 255)


def build_badge(source_path: Path, canvas_size: int, logo_fraction: float) -> Image.Image:
    canvas = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))

    # Filled white circle, no rim/ring, inscribed in the canvas.
    draw = ImageDraw.Draw(canvas)
    draw.ellipse((0, 0, canvas_size - 1, canvas_size - 1), fill=WHITE)

    logo = Image.open(source_path).convert("RGBA")

    # Drop the sub-threshold noise haze, then crop to the true mark.
    r, g, b, a = logo.split()
    a = a.point(lambda p: p if p >= NOISE_FLOOR else 0)
    logo = Image.merge("RGBA", (r, g, b, a))
    bbox = logo.getbbox()
    if bbox is not None:
        logo = logo.crop(bbox)

    # Scale the (near-square) mark so its longest side fills logo_fraction of the
    # disc, preserving aspect, and center it.
    target = int(canvas_size * logo_fraction)
    w, h = logo.size
    scale = target / max(w, h)
    logo = logo.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS)

    offset = ((canvas_size - logo.size[0]) // 2, (canvas_size - logo.size[1]) // 2)
    canvas.alpha_composite(logo, offset)

    return canvas


def main() -> None:
    badge = build_badge(SOURCE_LOGO, CANVAS_SIZE, LOGO_FRACTION_OF_CIRCLE)
    badge = badge.resize((FINAL_SIZE, FINAL_SIZE), Image.LANCZOS)
    OUTPUT_BADGE.parent.mkdir(parents=True, exist_ok=True)
    badge.save(OUTPUT_BADGE, format="PNG", optimize=True)
    print(f"wrote {OUTPUT_BADGE}")


if __name__ == "__main__":
    main()
