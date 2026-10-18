"""Builds design/themes.json from the published palette files.

Every canonical colour is read from those files, never typed; the only typed
colours are GoMesh's own five themes (GoMesh Light and Dark, Paper, and
Telegram Light and Dark). Anything derived or adjusted for contrast is
recorded in the theme's "notes". bridge/themes_test.go checks the result.

Besides the required tokens, a theme may set these optional ones, which the
app falls back from when a theme leaves them out:

    chatBg         the chat's background          (bg)
    chatPattern    the dots drawn on chatBg       (textMuted, faint)
    selectedRow    the chat list's selected row   (accent)
    onSelectedRow  text on selectedRow            (onAccent)
    metaOut        timestamps on bubbleOut        (onBubbleOut)
    metaIn         timestamps on bubbleIn         (onBubbleIn)
    tickRead       the "read" ticks on bubbleOut  (derived here for every theme)

    mkdir -p /tmp/palettes && cd /tmp/palettes
    curl -fsSLo catppuccin.json      https://raw.githubusercontent.com/catppuccin/palette/main/palette.json
    curl -fsSLo gruvbox.vim          https://raw.githubusercontent.com/morhetz/gruvbox/master/colors/gruvbox.vim
    curl -fsSLo solarized.md         https://raw.githubusercontent.com/altercation/solarized/master/README.md
    curl -fsSLo tokyonight-night.lua https://raw.githubusercontent.com/folke/tokyonight.nvim/main/lua/tokyonight/colors/night.lua
    curl -fsSLo tokyonight-storm.lua https://raw.githubusercontent.com/folke/tokyonight.nvim/main/lua/tokyonight/colors/storm.lua
    curl -fsSLo onedark-colors.less  https://raw.githubusercontent.com/atom/atom/master/packages/one-dark-syntax/styles/colors.less
    curl -fsSLo onelight-colors.less https://raw.githubusercontent.com/atom/atom/master/packages/one-light-syntax/styles/colors.less
    curl -fsSLo dracula.vim          https://raw.githubusercontent.com/dracula/vim/master/autoload/dracula.vim
    curl -fsSLo nord.css             https://raw.githubusercontent.com/nordtheme/nord/develop/src/nord.css
    curl -fsSLo rosepine.js          https://unpkg.com/@rose-pine/palette@4.0.1/dist/index.js
    curl -fsSLo primer-light.css     https://unpkg.com/@primer/primitives@11.10.0/dist/css/functional/themes/light.css
    curl -fsSLo primer-dark.css      https://unpkg.com/@primer/primitives@11.10.0/dist/css/functional/themes/dark.css
    python3 design/gen_themes.py /tmp/palettes design/themes.json
"""
import colorsys, json, re, sys
PAL = sys.argv[1]; OUT = sys.argv[2]

def rd(name): return open(f"{PAL}/{name}").read()

def lum(h):
    h = h.lstrip('#'); r, g, b = (int(h[i:i+2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)

def contrast(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)

def hsl_hex(h, s, l):
    r, g, b = colorsys.hls_to_rgb(h / 360, l / 100, s / 100)
    return '#%02x%02x%02x' % tuple(round(x * 255) for x in (r, g, b))

def shift(hexc, dl):
    h = hexc.lstrip('#'); r, g, b = (int(h[i:i+2], 16) / 255 for i in (0, 2, 4))
    hh, l, s = colorsys.rgb_to_hls(r, g, b)
    l = min(1, max(0, l + dl / 100))
    r, g, b = colorsys.hls_to_rgb(hh, l, s)
    return '#%02x%02x%02x' % tuple(round(x * 255) for x in (r, g, b))

def blend(top, under, alpha):
    t = [int(top.lstrip('#')[i:i+2], 16) for i in (0, 2, 4)]
    u = [int(under.lstrip('#')[i:i+2], 16) for i in (0, 2, 4)]
    return '#%02x%02x%02x' % tuple(round(alpha * a + (1 - alpha) * b) for a, b in zip(t, u))

# The avatar wash: the palette colour at this opacity over the surface it sits on.
WASH = 0.22

def fit(color, against, target, direction):
    """Moves color's lightness in direction (-1 darker, +1 lighter) until it
    reaches target contrast against `against`."""
    c = color
    for _ in range(100):
        if contrast(c, against) >= target: return c
        c = shift(c, direction)
    raise SystemExit(f"cannot fit {color} against {against}")

def away_from(ground):
    """The direction that adds contrast against ground: darker on a light one."""
    return -1 if lum(ground) > 0.179 else 1

def tick_read(c, notes):
    """The colour of the "read" ticks on the outgoing bubble: the theme's own
    when it sets one, else its success colour, either moved to 3:1 against
    bubbleOut. Ticks are shapes, not text, so 3:1 is the bar."""
    given = c.get('tickRead')
    t = fit(given or c['success'], c['bubbleOut'], 3.0, away_from(c['bubbleOut']))
    if given and t != given:
        notes.append(f"tickRead {given} -> {t} for 3:1 on bubbleOut")
    elif not given:
        notes.append(f"tickRead {t}: success moved to 3:1 on bubbleOut")
    return t

# --- sources ---
cat = json.load(open(f"{PAL}/catppuccin.json"))
def catp(flavor): return {k: v['hex'] for k, v in cat[flavor]['colors'].items()}

gb = dict(re.findall(r"let s:gb\.(\w+)\s*=\s*\['(#[0-9a-f]{6})'", rd('gruvbox.vim')))
sol = dict(re.findall(r"\$(\w+):\s*(#[0-9a-f]{6});", rd('solarized.md')))
storm = dict(re.findall(r"(\w+) = \"(#[0-9a-fA-F]{6})\"", rd('tokyonight-storm.lua')))
night = dict(storm, **dict(re.findall(r"(\w+) = \"(#[0-9a-fA-F]{6})\"", rd('tokyonight-night.lua'))))
night = {k: v.lower() for k, v in night.items()}
drac = {k: v.lower() for k, v in re.findall(r"palette\.(\w+)\s*=\s*\['(#[0-9A-Fa-f]{6})'", rd('dracula.vim'))}
nord = dict(re.findall(r"--(nord\d+): (#[0-9a-f]{6});", rd('nord.css')))
def rosepine(variant):
    js = rd('rosepine.js')
    block = js[js.index(f"const {variant} = {{"):]
    block = block[:block.index("\n};")]
    return {k: '#' + v for k, v in re.findall(r"^    (\w+): \{\s*hex: \"([0-9a-f]{6})\"", block, re.M)}
def primer(th):
    css = rd(f'primer-{th}.css')
    d = {}
    for k, v in re.findall(r"--([\w-]+): (#[0-9a-f]{6,8}|var\(--[\w-]+\));", css):
        d.setdefault(k, v)
    class Resolved(dict):
        def __missing__(self, k): raise KeyError(k)
        def __getitem__(self, k):
            v = d[k]
            while v.startswith('var('): v = d[v[6:-1]]
            return v
    return Resolved()
def one(name):
    less = rd(name)
    hue = int(re.search(r"@syntax-hue:\s*(\d+)", less).group(1))
    sat = int(re.search(r"@syntax-saturation:\s*(\d+)%", less).group(1))
    bri = int(re.search(r"@syntax-brightness:\s*(\d+)%", less).group(1))
    v = {}
    for k, h, s, l in re.findall(r"@([\w-]+):\s*hsl\(\s*(@syntax-hue|\d+),\s*(\d+)%,\s*(\d+)%\s*\)", less):
        v[k] = hsl_hex(hue if h == '@syntax-hue' else int(h), int(s), int(l))
    v['bg'] = hsl_hex(hue, sat, bri)
    return v

SRC = {
    'catppuccin': 'https://github.com/catppuccin/palette/blob/main/palette.json',
    'gruvbox': 'https://github.com/morhetz/gruvbox/blob/master/colors/gruvbox.vim',
    'solarized': 'https://github.com/altercation/solarized#the-values',
    'tokyonight': 'https://github.com/folke/tokyonight.nvim/tree/main/lua/tokyonight/colors (night.lua over storm.lua)',
    'dracula': 'https://github.com/dracula/vim/blob/master/autoload/dracula.vim',
    'nord': 'https://github.com/nordtheme/nord/blob/develop/src/nord.css',
    'rosepine': 'https://www.npmjs.com/package/@rose-pine/palette (dist/index.js, v4.0.1)',
    'primer': 'https://www.npmjs.com/package/@primer/primitives (dist/css/functional/themes, v11.10.0)',
    'one-dark': 'https://github.com/atom/atom/blob/master/packages/one-dark-syntax/styles/colors.less',
    'one-light': 'https://github.com/atom/atom/blob/master/packages/one-light-syntax/styles/colors.less',
}

OPTIONAL = ['chatBg', 'chatPattern', 'selectedRow', 'onSelectedRow', 'metaOut', 'metaIn', 'tickRead']

themes = []
def add(id, name, appearance, source, c, notes=None):
    notes = list(notes or [])
    dark = appearance == 'dark'
    away = 1 if dark else -1  # the direction that adds contrast against the background
    c = dict(c)
    c.setdefault('onBubbleIn', c['text'])
    c.setdefault('bubbleIn', c['surfaceRaised'])
    c.setdefault('bubbleOut', c['accent'])
    # Text on the accent: whichever of the theme's own ends reads best.
    if 'onAccent' not in c:
        c['onAccent'] = max([c['bg'], c['text'], '#ffffff', c.get('ink', '#000000')], key=lambda x: contrast(x, c['accent']))
    if contrast(c['onAccent'], c['accent']) < 4.5:
        old = c['accent']
        c['accent'] = fit(old, c['onAccent'], 4.5, -1 if lum(c['onAccent']) > lum(old) else 1)
        notes.append(f"accent {old} -> {c['accent']} so its label reads at 4.5:1")
    c.setdefault('onBubbleOut', c['onAccent'])
    if contrast(c['onBubbleOut'], c['bubbleOut']) < 4.5:
        old = c['bubbleOut']
        c['bubbleOut'] = fit(old, c['onBubbleOut'], 4.5, -1 if lum(c['onBubbleOut']) > lum(old) else 1)
        notes.append(f"bubbleOut {old} -> {c['bubbleOut']}: the canonical accent is kept, only the bubble is adjusted for 4.5:1")
    # Optional tokens. Text on them is held to 4.5:1 like any other text.
    if 'selectedRow' in c or 'onSelectedRow' in c:
        c.setdefault('selectedRow', c['accent'])
        c.setdefault('onSelectedRow', c['onAccent'])
        if contrast(c['onSelectedRow'], c['selectedRow']) < 4.5:
            old = c['selectedRow']
            c['selectedRow'] = fit(old, c['onSelectedRow'], 4.5, -1 if lum(c['onSelectedRow']) > lum(old) else 1)
            notes.append(f"selectedRow {old} -> {c['selectedRow']} so its label reads at 4.5:1")
    for key in ('metaOut', 'metaIn'):
        ground = 'bubbleOut' if key == 'metaOut' else 'bubbleIn'
        if key in c and contrast(c[key], c[ground]) < 4.5:
            old = c[key]
            c[key] = fit(old, c[ground], 4.5, away_from(c[ground]))
            notes.append(f"{key} {old} -> {c[key]} for 4.5:1 on {ground}")
    chat_grounds = ('chatBg',) if 'chatBg' in c else ()
    for key, target, grounds in (('text', 4.5, ('bg', 'surface', 'surfaceRaised')), ('textMuted', 4.5, ('bg', 'surface', 'surfaceRaised') + chat_grounds),
                                 ('onBubbleIn', 4.5, ('bubbleIn',)), ('danger', 4.5, ('bg', 'surface') + chat_grounds), ('warning', 3.0, ('bg',)), ('success', 3.0, ('bg',))):
        for ground in grounds:
            if contrast(c[key], c[ground]) < target:
                old = c[key]
                c[key] = fit(old, c[ground], target, away)
                notes.append(f"{key} {old} -> {c[key]} for {target}:1 on {ground}")
    c.pop('ink', None)
    c['tickRead'] = tick_read(c, notes)
    # accentText: the accent as text and as the tint of buttons and links, on
    # bg and surface. The accent itself stays for fills.
    at = c['accent']
    for ground in ('bg', 'surface'):
        if contrast(at, c[ground]) < 4.5:
            at = fit(at, c[ground], 4.5, away)
    c['accentText'] = at
    if at != c['accent']:
        notes.append(f"accentText {at}: the accent {'darkened' if away < 0 else 'lightened'} to read as text at 4.5:1 on bg and surface")
    # paletteText: the palette as text, for sender names on the incoming bubble
    # (4.5:1) and for an avatar's letter on its own wash (3:1, a large letter).
    pt = []
    adjusted = 0
    for col in c['palette']:
        t = col
        for _ in range(100):
            ok = contrast(t, c['bubbleIn']) >= 4.5 and all(
                contrast(t, blend(col, ground, WASH)) >= 3.0 for ground in (c['surface'], c['bg']))
            if ok:
                break
            t = shift(t, away)
        else:
            raise SystemExit(f"{name}: cannot fit palette colour {col} as text")
        adjusted += t != col
        pt.append(t)
    c['paletteText'] = pt
    if adjusted:
        notes.append(f"paletteText: {adjusted} of the 8 palette colours are {'darkened' if away < 0 else 'lightened'} to read as text (4.5:1 on bubbleIn, 3:1 on their avatar wash)")
    order = ['bg', 'surface', 'surfaceRaised', 'border', 'text', 'textMuted', 'accent', 'accentText', 'onAccent',
             'bubbleOut', 'onBubbleOut', 'bubbleIn', 'onBubbleIn', 'danger', 'warning', 'success']
    order += [k for k in OPTIONAL if k in c] + ['palette', 'paletteText']
    t = {'id': id, 'name': name, 'appearance': appearance, 'source': source,
         'colors': {k: (c[k].lower() if isinstance(c[k], str) else [x.lower() for x in c[k]]) for k in order}}
    if notes: t['notes'] = notes
    themes.append(t)

# --- light ---
# A Telegram-inspired pair: white sidebar, a solid-blue selected row, pale green
# outgoing bubbles on a dotted green-grey background. GoMesh's own values, not
# Telegram's files. The reference timestamps and ticks are pale green on pale
# green; they are darkened here to 4.5:1 (timestamps) and 3:1 (ticks).
add('telegram-light', 'Telegram Light', 'light', 'original', dict(
    bg='#f1f3f5', surface='#ffffff', surfaceRaised='#f1f3f4', border='#e4e7ea', text='#0f1419', textMuted='#707579',
    chatBg='#e6ebdf', chatPattern='#cbd6c1',
    accent='#3390ec', onAccent='#ffffff', danger='#e53935', warning='#9a6300', success='#2e9d57',
    bubbleOut='#eeffde', onBubbleOut='#0f1419', metaOut='#4fae4e', tickRead='#4fae4e',
    bubbleIn='#ffffff', onBubbleIn='#0f1419', metaIn='#a0acb6',
    palette=['#e17076', '#e8803a', '#c9a227', '#5fae48', '#2fa7ab', '#4a93d2', '#8f7bd9', '#e0629d']))
add('gomesh-light', 'GoMesh Light', 'light', 'original', dict(
    bg='#f6f7fb', surface='#ffffff', surfaceRaised='#eceef5', border='#dfe2ec', text='#161821', textMuted='#5b6275',
    accent='#5b4fe9', onAccent='#ffffff', danger='#c8242f', warning='#9a6300', success='#1a7f45',
    palette=['#e5484d', '#e2640f', '#c08800', '#2f9a5f', '#12a594', '#0b7ee8', '#8e4ec6', '#d6409f']))
add('paper', 'Paper', 'light', 'original', dict(
    bg='#f4efe6', surface='#fbf8f2', surfaceRaised='#ebe4d6', border='#ddd3c2', text='#2a251e', textMuted='#625a4e',
    accent='#a0522d', onAccent='#ffffff', danger='#a8241c', warning='#7d5800', success='#3a7044',
    palette=['#b3261e', '#c2571a', '#a07800', '#4f7d3a', '#2f7c78', '#2f5d8a', '#6e4a8e', '#a8466e']))
l = catp('latte')
add('catppuccin-latte', 'Catppuccin Latte', 'light', SRC['catppuccin'], dict(
    bg=l['base'], surface=l['mantle'], surfaceRaised=l['surface0'], border=l['surface1'], text=l['text'], textMuted=l['subtext0'],
    accent=l['mauve'], ink=l['crust'], danger=l['red'], warning=l['yellow'], success=l['green'],
    palette=[l['red'], l['peach'], l['yellow'], l['green'], l['teal'], l['blue'], l['mauve'], l['pink']]))
o = one('onelight-colors.less')
add('one-light', 'One Light', 'light', SRC['one-light'], dict(
    bg=o['bg'], surface=shift(o['bg'], -3), surfaceRaised=shift(o['bg'], -6), border=shift(o['bg'], -10), text=o['mono-1'], textMuted=o['mono-2'],
    accent=o['hue-2'], danger=o['hue-5-2'], warning=o['hue-6'], success=o['hue-4'],
    palette=[o['hue-5'], o['hue-6-2'], o['hue-6'], o['hue-4'], o['hue-1'], o['hue-2'], o['hue-3'], o['hue-5-2']]),
    ["surface, surfaceRaised and border are the background darkened by 3, 6 and 10 points of lightness: One Light defines only the editor background"])
add('gruvbox-light', 'Gruvbox Light', 'light', SRC['gruvbox'], dict(
    bg=gb['light0'], surface=gb['light0_hard'], surfaceRaised=gb['light1'], border=gb['light2'], text=gb['dark1'], textMuted=gb['dark3'],
    accent=gb['faded_orange'], danger=gb['faded_red'], warning=gb['faded_yellow'], success=gb['faded_green'],
    palette=[gb['faded_red'], gb['faded_orange'], gb['faded_yellow'], gb['faded_green'], gb['faded_aqua'], gb['faded_blue'], gb['faded_purple'], gb['neutral_purple']]),
    ["Gruvbox has no pink; palette pink is neutral_purple"])
add('solarized-light', 'Solarized Light', 'light', SRC['solarized'], dict(
    bg=sol['base3'], surface=sol['base2'], surfaceRaised=sol['base2'], border=sol['base1'], text=sol['base01'], textMuted=sol['base00'],
    accent=sol['blue'], danger=sol['red'], warning=sol['yellow'], success=sol['green'],
    palette=[sol['red'], sol['orange'], sol['yellow'], sol['green'], sol['cyan'], sol['blue'], sol['violet'], sol['magenta']]),
    ["text is base01, Solarized's emphasized content, since base00 is below 4.5:1 on base3"])
d = rosepine('dawn')
add('rose-pine-dawn', 'Rosé Pine Dawn', 'light', SRC['rosepine'], dict(
    bg=d['base'], surface=d['surface'], surfaceRaised=d['overlay'], border=d['highlightMed'], text=d['text'], textMuted=d['subtle'],
    accent=d['iris'], danger=d['love'], warning=d['gold'], success=d['pine'],
    palette=[d['love'], d['rose'], d['gold'], d['pine'], d['foam'], d['pine'], d['iris'], d['love']]),
    ["Rosé Pine has six accents: palette green and blue are both pine, pink is love"])
p = primer('light')
add('github-light', 'GitHub Light', 'light', SRC['primer'], dict(
    bg=p['bgColor-default'], surface=p['bgColor-muted'], surfaceRaised=p['bgColor-muted'], border=p['borderColor-default'],
    text=p['fgColor-default'], textMuted=p['fgColor-muted'], accent=p['bgColor-accent-emphasis'], onAccent=p['fgColor-onEmphasis'],
    danger=p['fgColor-danger'], warning=p['fgColor-attention'], success=p['fgColor-success'],
    palette=[p[f'display-{n}-fgColor'] for n in ('red', 'orange', 'yellow', 'green', 'teal', 'blue', 'purple', 'pink')]))

# --- dark ---
add('telegram-dark', 'Telegram Dark', 'dark', 'original', dict(
    bg='#1c1c1c', surface='#282828', surfaceRaised='#333333', border='#3a3a3a', text='#f5f5f5', textMuted='#9a9a9f',
    chatPattern='#1c1c1c',
    accent='#0a74e0', accentText='#4da3ff', onAccent='#ffffff', selectedRow='#0062cb', onSelectedRow='#ffffff',
    danger='#ff6b6b', warning='#f5b341', success='#4fd07e',
    bubbleOut='#0363ce', onBubbleOut='#ffffff', metaOut='#e3efff', tickRead='#8fd0ff',
    bubbleIn='#313131', onBubbleIn='#f5f5f5', metaIn='#9a9a9f',
    palette=['#ff7a85', '#ff9a56', '#f0c24b', '#6fd35a', '#4fd1c5', '#5cb2ff', '#b59cff', '#ff8cc0']))
add('gomesh-dark', 'GoMesh Dark', 'dark', 'original', dict(
    bg='#0e1016', surface='#151821', surfaceRaised='#1e2230', border='#2a2f3d', text='#e9ebf3', textMuted='#9ca3b8',
    accent='#8b80ff', onAccent='#0e1016', bubbleOut='#6153f0', onBubbleOut='#ffffff', danger='#ff6b6b', warning='#f5b341', success='#3dd68c',
    palette=['#ff6369', '#ff8b3e', '#ffd60a', '#3dd68c', '#0bd8b6', '#52a9ff', '#bf7af0', '#f986c9']))
for flavor, name in (('mocha', 'Catppuccin Mocha'), ('macchiato', 'Catppuccin Macchiato')):
    m = catp(flavor)
    add(f'catppuccin-{flavor}', name, 'dark', SRC['catppuccin'], dict(
        bg=m['base'], surface=m['mantle'], surfaceRaised=m['surface0'], border=m['surface1'], text=m['text'], textMuted=m['subtext0'],
        accent=m['mauve'], ink=m['crust'], danger=m['red'], warning=m['yellow'], success=m['green'],
        palette=[m['red'], m['peach'], m['yellow'], m['green'], m['teal'], m['blue'], m['mauve'], m['pink']]))
o = one('onedark-colors.less')
add('one-dark', 'One Dark', 'dark', SRC['one-dark'], dict(
    bg=o['bg'], surface=shift(o['bg'], -3), surfaceRaised=shift(o['bg'], 4), border=shift(o['bg'], 9), text=o['mono-1'], textMuted=o['mono-2'],
    accent=o['hue-2'], danger=o['hue-5'], warning=o['hue-6-2'], success=o['hue-4'],
    palette=[o['hue-5'], o['hue-6'], o['hue-6-2'], o['hue-4'], o['hue-1'], o['hue-2'], o['hue-3'], o['hue-5-2']]),
    ["surface, surfaceRaised and border are the background shifted by -3, +4 and +9 points of lightness: One Dark defines only the editor background"])
add('gruvbox-dark', 'Gruvbox Dark', 'dark', SRC['gruvbox'], dict(
    bg=gb['dark0'], surface=gb['dark0_hard'], surfaceRaised=gb['dark1'], border=gb['dark2'], text=gb['light1'], textMuted=gb['light4'],
    accent=gb['bright_orange'], danger=gb['bright_red'], warning=gb['bright_yellow'], success=gb['bright_green'],
    palette=[gb['bright_red'], gb['bright_orange'], gb['bright_yellow'], gb['bright_green'], gb['bright_aqua'], gb['bright_blue'], gb['bright_purple'], gb['neutral_purple']]),
    ["Gruvbox has no pink; palette pink is neutral_purple"])
add('dracula', 'Dracula', 'dark', SRC['dracula'], dict(
    bg=drac['bg'], surface=drac['bgdark'], surfaceRaised=drac['bglight'], border=drac['selection'], text=drac['fg'], textMuted=drac['comment'],
    accent=drac['purple'], danger=drac['red'], warning=drac['yellow'], success=drac['green'],
    palette=[drac['red'], drac['orange'], drac['yellow'], drac['green'], drac['cyan'], drac['comment'], drac['purple'], drac['pink']]),
    ["Dracula has no blue; palette blue is comment"])
add('nord', 'Nord', 'dark', SRC['nord'], dict(
    bg=nord['nord0'], surface=nord['nord1'], surfaceRaised=nord['nord2'], border=nord['nord3'], text=nord['nord6'], textMuted=nord['nord4'],
    accent=nord['nord8'], danger=nord['nord11'], warning=nord['nord13'], success=nord['nord14'],
    palette=[nord['nord11'], nord['nord12'], nord['nord13'], nord['nord14'], nord['nord7'], nord['nord10'], nord['nord15'], nord['nord15']]),
    ["Nord has no pink; palette pink is nord15, as purple is"])
add('tokyo-night', 'Tokyo Night', 'dark', SRC['tokyonight'], dict(
    bg=night['bg'], surface=night['bg_dark'], surfaceRaised=night['bg_highlight'], border=night['fg_gutter'], text=night['fg'], textMuted=night['fg_dark'],
    accent=night['blue'], danger=night['red'], warning=night['yellow'], success=night['green'],
    palette=[night['red'], night['orange'], night['yellow'], night['green'], night['teal'], night['blue'], night['magenta'], night['magenta2']]))
add('solarized-dark', 'Solarized Dark', 'dark', SRC['solarized'], dict(
    bg=sol['base03'], surface=sol['base02'], surfaceRaised=sol['base02'], border=sol['base01'], text=sol['base1'], textMuted=sol['base0'],
    accent=sol['blue'], danger=sol['red'], warning=sol['yellow'], success=sol['green'],
    palette=[sol['red'], sol['orange'], sol['yellow'], sol['green'], sol['cyan'], sol['blue'], sol['violet'], sol['magenta']]),
    ["text is base1, Solarized's emphasized content, and textMuted base0, its body text"])
for variant, id, name in (('main', 'rose-pine', 'Rosé Pine'), ('moon', 'rose-pine-moon', 'Rosé Pine Moon')):
    r = rosepine(variant)
    add(id, name, 'dark', SRC['rosepine'], dict(
        bg=r['base'], surface=r['surface'], surfaceRaised=r['overlay'], border=r['highlightMed'], text=r['text'], textMuted=r['subtle'],
        accent=r['iris'], danger=r['love'], warning=r['gold'], success=r['foam'],
        palette=[r['love'], r['rose'], r['gold'], r['foam'], r['foam'], r['pine'], r['iris'], r['love']]),
        ["Rosé Pine has six accents: palette green and teal are both foam, pink is love"])
p = primer('dark')
add('github-dark', 'GitHub Dark', 'dark', SRC['primer'], dict(
    bg=p['bgColor-default'], surface=p['bgColor-muted'], surfaceRaised=p['bgColor-muted'], border=p['borderColor-default'],
    text=p['fgColor-default'], textMuted=p['fgColor-muted'], accent=p['bgColor-accent-emphasis'], onAccent=p['fgColor-onEmphasis'],
    danger=p['fgColor-danger'], warning=p['fgColor-attention'], success=p['fgColor-success'],
    palette=[p[f'display-{n}-fgColor'] for n in ('red', 'orange', 'yellow', 'green', 'teal', 'blue', 'purple', 'pink')]))

out = {'version': 1,
       'about': "GoMesh's themes. Each names the published palette its colors come from; notes record every color derived or adjusted for contrast. The Go test in bridge/themes_test.go checks them.",
       'themes': themes}
open(OUT, 'w').write(json.dumps(out, indent=2, ensure_ascii=False) + '\n')
for t in themes:
    c = t['colors']
    print(f"{t['name']:22} text {contrast(c['text'], c['bg']):5.2f} muted {contrast(c['textMuted'], c['bg']):5.2f} accent {contrast(c['onAccent'], c['accent']):5.2f} out {contrast(c['onBubbleOut'], c['bubbleOut']):5.2f} in {contrast(c['onBubbleIn'], c['bubbleIn']):5.2f}", '|', '; '.join(t.get('notes', [])))
