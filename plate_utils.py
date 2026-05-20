"""
Ethiopian License Plate Utilities — strict multi-format validation.

VALID FORMATS
─────────────
  Standard:    {1-5} {REGION} {[A-Z]?NNNNN}   e.g.  2 AA 12345
  Diplomatic:  {01-132} {REGION} {[A-Z]?NNNNN} e.g. 01 AA 12345
  UN:           UN {NNNNN}                       e.g. UN 12345
  AU:           AU {NNNNN}                       e.g. AU 12345
  Temporary:   TT {NNNNN}                        e.g. TT 99999

REGION CODES  (AA OR AM TG SN AF SM BG GM HR DD DR ET)
STRICT RULE   Exactly one space between parts. All uppercase. No dashes.
"""

import re

# ── Region codes ──────────────────────────────────────────────────────────────

REGIONS = {
    'ET': 'Ethiopia',
    'AA': 'Addis Ababa',
    'AF': 'Afar',
    'AM': 'Amhara',
    'BG': 'Benishangul-Gumuz',
    'DR': 'Dire Dawa',
    'DD': 'Dire Dawa',       # legacy alias
    'GM': 'Gambela',
    'HR': 'Harar',
    'OR': 'Oromia',
    'SM': 'Somali',
    'TG': 'Tigray',          # legacy
    'SN': 'SNNPR',           # legacy
}

ET_REGIONS = frozenset(REGIONS.keys())

# ── Vehicle category codes ────────────────────────────────────────────────────

VEHICLE_CATEGORIES = {
    '1':  {'name': 'Taxi',           'name_am': 'ታክሲ',              'sort_order': 1},
    '2':  {'name': 'Private',        'name_am': 'የግል',              'sort_order': 2},
    '3':  {'name': 'Commercial',     'name_am': 'ንግድ',              'sort_order': 3},
    '4':  {'name': 'Government',     'name_am': 'መንግሥት',           'sort_order': 4},
    '5':  {'name': 'Red Cross',      'name_am': 'ቀይ መስቀል',         'sort_order': 5},
    'UN': {'name': 'United Nations', 'name_am': 'የተባበሩት መንግሥታት', 'sort_order': 6},
    'AU': {'name': 'African Union',  'name_am': 'አፍሪካ ህብረት',      'sort_order': 7},
    'TT': {'name': 'Temporary',      'name_am': 'ተላላፊ',             'sort_order': 8},
}

# ── Diplomatic codes ──────────────────────────────────────────────────────────

DIPLOMATIC_CODES = {
    '01': 'Italy',            '02': 'France',              '03': 'United Kingdom',
    '04': 'United States',    '05': 'Belgium',              '06': 'Turkey',
    '07': 'Egypt',            '08': 'Greece',               '09': 'Czech Republic',
    '10': 'Russia',           '11': 'Sweden',               '12': 'India',
    '13': 'Yugoslavia',       '14': 'Germany',              '15': 'Netherlands',
    '16': 'Yemen',            '17': 'Mexico',               '18': 'Saudi Arabia',
    '19': 'Switzerland',      '20': 'Sudan',                '21': 'Vatican',
    '22': 'Bulgaria',         '23': 'Japan',                '24': 'Liberia',
    '25': 'Ghana',            '26': 'Spain',                '27': 'Poland',
    '28': 'Somalia',          '29': 'Iran',                 '30': 'Nigeria',
    '31': 'Malawi',           '32': 'Senegal',              '33': 'Zaire',
    '34': 'Tanzania',         '35': 'Indonesia',            '36': 'Austria',
    '37': 'South Korea',      '38': 'Malaysia',             '39': 'Burundi',
    '40': 'Zambia',           '41': None,                   '42': 'Morocco',
    '43': 'Finland',          '44': 'Thailand',             '45': 'Hungary',
    '46': 'Canada',           '47': 'Ivory Coast',          '48': 'Cameroon',
    '49': 'Kenya',            '50': 'Equatorial Guinea',    '51': 'Venezuela',
    '52': 'Sierra Leone',     '53': 'Rwanda',               '54': 'Guinea',
    '55': 'Jamaica',          '56': 'China',                '57': 'Mali',
    '58': 'Uganda',           '59': 'Argentina',            '60': None,
    '61': 'Pakistan',         '62': 'Gabon',                '63': 'Libya',
    '64': 'Romania',          '65': None,                   '66': 'Cuba',
    '67': 'Niger',            '68': 'North Korea',          '69': 'Algeria',
    '70': 'Vietnam',          '71': 'Djibouti',             '72': 'Zimbabwe',
    '73': 'Congo',            '74': 'Chad',                 '75': 'Mozambique',
    '76': 'Australia',        '77': 'Tunisia',              '78': 'Afghanistan',
    '79': 'Nicaragua',        '80': None,                   '81': 'Palestine',
    '82': 'Angola',           '83': 'Iraq',                 '84': 'Israel',
    '85': 'Madagascar',       '86': 'Norway',               '87': 'Namibia',
    '88': 'Mali',             '89': None,                   '90': 'Eritrea',
    '91': 'Ireland',          '92': 'South Africa',         '93': 'Lesotho',
    '94': 'Mauritius',        '95': 'Kuwait',               '96': 'Burkina Faso',
    '97': 'Botswana',         '98': 'Cape Verde',           '99': 'Togo',
    '100': 'Portugal',        '101': 'Gambia',              '102': 'Benin',
    '103': 'Mauritania',      '104': 'Ukraine',             '105': 'Denmark',
    '106': None,              '107': 'Brazil',              '108': 'Slovakia',
    '109': 'United Arab Emirates',
    '110': 'League of Arab States',
    '111': 'South Sudan',     '112': 'Luxembourg',          '113': 'Comoros',
    '114': 'Georgia',         '115': 'Seychelles',          '116': 'Qatar',
    '132': 'Armenia',
}

RESERVED_CODES = frozenset(k for k, v in DIPLOMATIC_CODES.items() if v is None)

# Aliases used by database.py seed functions
DEFAULT_VEHICLE_CATEGORIES  = VEHICLE_CATEGORIES
DEFAULT_REGIONS             = REGIONS
DEFAULT_DIPLOMATIC_CODES    = DIPLOMATIC_CODES
RESERVED_DIPLOMATIC_CODES   = RESERVED_CODES

# ── Regex constants ───────────────────────────────────────────────────────────

_REGION_ALT   = '|'.join(sorted(ET_REGIONS, key=len, reverse=True))
_SERIAL_PART  = r'[A-Z]?\d{5}'      # optional letter + exactly 5 digits

# Standard plate:   {1-5} REGION SERIAL
_STD_RE = re.compile(
    r'^([1-5])\s(' + _REGION_ALT + r')\s(' + _SERIAL_PART + r')$'
)

# Diplomatic plate: {01-132} REGION SERIAL
_DIPL_RE = re.compile(
    r'^(\d{1,3})\s(' + _REGION_ALT + r')\s(' + _SERIAL_PART + r')$'
)

# UN / AU plates: CODE NNNNN
_UN_RE  = re.compile(r'^UN\s(\d{1,5})$')
_AU_RE  = re.compile(r'^AU\s(\d{1,5})$')

# Temporary: TT NNNNN  (also accept legacy ተላላፊ)
_TT_RE  = re.compile(r'^TT\s(\d{1,5})$')
_TEMP_RE = re.compile(r'^ተላላፊ\s(\d{1,5})$')


# ── Normalisation helpers ─────────────────────────────────────────────────────

def _pad_dipl(code_str):
    """Pad diplomatic code: '4' → '04', '10' → '10', '100' → '100'."""
    try:
        n = int(code_str)
        return '{:02d}'.format(n) if n < 100 else str(n)
    except (ValueError, TypeError):
        return code_str


def _collapse(plate):
    """Uppercase and collapse all whitespace runs to single spaces."""
    return re.sub(r'\s+', ' ', plate.strip().upper())


# ── Main classify function ────────────────────────────────────────────────────

def classify_plate(raw):
    """
    Returns a dict with keys:
      plate_type        : 'standard' | 'diplomatic' | 'un' | 'au' | 'temporary' | 'unknown'
      normalized        : canonical string (e.g. '2 AA 12345')
      valid             : bool
      region            : str | None
      vehicle_category  : str | None
      is_diplomatic     : bool
      diplomatic_code   : str | None
      diplomatic_country: str | None
      mission_type      : None  (kept for API compatibility)
      organization_type : str | None
    """
    if not raw:
        return _unknown('')

    p = _collapse(raw)

    # ── UN ───────────────────────────────────────────────────────────────────
    m = _UN_RE.match(p)
    if m:
        return {
            'plate_type': 'un',         'normalized': 'UN {}'.format(m.group(1)),
            'valid': True,              'region': None,
            'vehicle_category': 'UN',   'is_diplomatic': True,
            'diplomatic_code': None,    'diplomatic_country': None,
            'mission_type': None,       'organization_type': 'United Nations',
        }

    # ── AU ───────────────────────────────────────────────────────────────────
    m = _AU_RE.match(p)
    if m:
        return {
            'plate_type': 'au',         'normalized': 'AU {}'.format(m.group(1)),
            'valid': True,              'region': None,
            'vehicle_category': 'AU',   'is_diplomatic': True,
            'diplomatic_code': None,    'diplomatic_country': None,
            'mission_type': None,       'organization_type': 'African Union',
        }

    # ── Temporary ────────────────────────────────────────────────────────────
    m = _TT_RE.match(p) or _TEMP_RE.match(p)
    if m:
        return {
            'plate_type': 'temporary',  'normalized': 'TT {}'.format(m.group(1)),
            'valid': True,              'region': None,
            'vehicle_category': 'TT',   'is_diplomatic': False,
            'diplomatic_code': None,    'diplomatic_country': None,
            'mission_type': None,       'organization_type': None,
        }

    # ── Standard vehicle plate ────────────────────────────────────────────────
    m = _STD_RE.match(p)
    if m:
        code, region, serial = m.group(1), m.group(2), m.group(3)
        return {
            'plate_type': 'standard',           'normalized': '{} {} {}'.format(code, region, serial),
            'valid': True,                      'region': region,
            'vehicle_category': code,           'is_diplomatic': False,
            'diplomatic_code': None,            'diplomatic_country': None,
            'mission_type': None,               'organization_type': None,
        }

    # ── Diplomatic plate ──────────────────────────────────────────────────────
    m = _DIPL_RE.match(p)
    if m:
        raw_code, region, serial = m.group(1), m.group(2), m.group(3)
        code = _pad_dipl(raw_code)
        num  = int(raw_code)
        if num < 1 or num > 132 or code not in DIPLOMATIC_CODES:
            return _unknown(p)
        country = DIPLOMATIC_CODES[code]
        return {
            'plate_type': 'diplomatic',         'normalized': '{} {} {}'.format(code, region, serial),
            'valid': True,                      'region': region,
            'vehicle_category': None,           'is_diplomatic': True,
            'diplomatic_code': code,            'diplomatic_country': country or 'Reserved ({})'.format(code),
            'mission_type': None,               'organization_type': 'Diplomatic Mission',
        }

    return _unknown(p)


def _unknown(p):
    return {
        'plate_type': 'unknown',    'normalized': p.upper() if p else '',
        'valid': False,             'region': None,
        'vehicle_category': None,   'is_diplomatic': False,
        'diplomatic_code': None,    'diplomatic_country': None,
        'mission_type': None,       'organization_type': None,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def validate_plate(plate):
    """Return True if plate is valid in any supported format."""
    return classify_plate(plate)['valid']


def normalize_plate(plate):
    """Return canonical form, or empty string if invalid."""
    if not plate:
        return ''
    info = classify_plate(plate)
    return info['normalized'] if info['valid'] else ''


def lookup_diplomatic(code):
    padded = _pad_dipl(code)
    if padded not in DIPLOMATIC_CODES:
        return None
    return {
        'code': padded,
        'country': DIPLOMATIC_CODES[padded] or 'Reserved',
        'is_reserved': padded in RESERVED_CODES,
    }


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    tests = [
        # (input,              expected_type,  expected_valid, expected_norm)
        ('2 AA 12345',         'standard',     True,  '2 AA 12345'),
        ('1 OR A12345',        'standard',     True,  '1 OR A12345'),
        ('4 ET 54321',         'standard',     True,  '4 ET 54321'),
        ('5 DD Z99999',        'standard',     True,  '5 DD Z99999'),
        ('01 AA 12345',        'diplomatic',   True,  '01 AA 12345'),
        ('04 OR A12345',       'diplomatic',   True,  '04 OR A12345'),
        ('4 OR A12345',        'diplomatic',   True,  '04 OR A12345'),  # auto-pad
        ('132 AA 12345',       'diplomatic',   True,  '132 AA 12345'),
        ('UN 12345',           'un',           True,  'UN 12345'),
        ('AU 54321',           'au',           True,  'AU 54321'),
        ('TT 99999',           'temporary',    True,  'TT 99999'),
        ('ተላላፊ 12345',        'temporary',    True,  'TT 12345'),
        # Invalid
        ('AA 12345',           'unknown',      False, 'AA 12345'),   # missing code prefix
        ('01AA12345',          'unknown',      False, None),         # no spaces
        ('00 AA 12345',        'unknown',      False, None),         # code 0 invalid
        ('133 AA 12345',       'unknown',      False, None),         # code too high
        ('6 AA 12345',         'unknown',      False, None),         # vehicle code 6 invalid
        ('01 XX 12345',        'unknown',      False, None),         # invalid region
        ('01 AA 1234',         'unknown',      False, None),         # 4 digits
        ('01 AA 123456',       'unknown',      False, None),         # 6 digits
        ('',                   'unknown',      False, ''),
    ]
    print('=== plate_utils self-test ===')
    all_ok = True
    for t in tests:
        raw, exp_type, exp_valid = t[0], t[1], t[2]
        exp_norm = t[3] if len(t) > 3 else None
        info = classify_plate(raw)
        ok = info['plate_type'] == exp_type and info['valid'] == exp_valid
        if exp_norm is not None and exp_valid:
            ok = ok and info['normalized'] == exp_norm
        if not ok:
            all_ok = False
        print('  {} {!r:25} → type={} valid={} norm={!r}'.format(
            'OK  ' if ok else 'FAIL', raw, info['plate_type'], info['valid'], info['normalized']))
    print('All OK' if all_ok else 'FAILURES detected')
