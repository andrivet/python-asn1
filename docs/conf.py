# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import sys
sys.path.insert(0, os.path.abspath('../src'))

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.coverage',
    'sphinx.ext.doctest',
    'sphinx.ext.extlinks',
    'sphinx.ext.ifconfig',
    'sphinx.ext.napoleon',
    'sphinx.ext.todo',
    'sphinx.ext.viewcode',
]
if os.getenv('SPELLCHECK'):
    extensions += 'sphinxcontrib.spelling',
    spelling_show_suggestions = True
    spelling_lang = 'en_US'

source_suffix = '.rst'
master_doc = 'index'
project = 'Python-ASN1'
year = '2007-2022'
author = 'Sebastien Andrivet'
copyright = '{0}, {1}'.format(year, author)
version = release = '3.1.0'

pygments_style = 'trac'
templates_path = ['.']
extlinks = {
    'issue': ('https://github.com/andrivet/python-asn1/issues/%s', '#'),
    'pr': ('https://github.com/andrivet/python-asn1/pull/%s', 'PR #'),
}

html_theme = "sphinx_rtd_theme"
html_theme_options = {
}

html_use_smartypants = True
html_last_updated_fmt = '%b %d, %Y'
html_split_index = False
html_sidebars = {
   '**': ['searchbox.html', 'globaltoc.html', 'sourcelink.html'],
}
html_short_title = '%s-%s' % (project, version)

napoleon_use_ivar = True
napoleon_use_rtype = False
napoleon_use_param = False

suppress_warnings = ['image.nonlocal_uri']
default_role = 'any'

linkcheck_anchors = False
