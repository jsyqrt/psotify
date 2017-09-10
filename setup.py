#!/usr/bin/env python3

from distutils.core import setup

LONG_DESCRIPTION = '''
psotify,a python spotify album and artist info downloader
'''
setup(name = 'psotify',
      version = '0.0.1',
      description = 'psotify,a python spotify album and artist info downloader.',
      long_description = LONG_DESCRIPTION,
      author = 'Jason Carter',
      author_email = 'jsyqrt@gmail.com',
      url = 'https://github.com/jsyqrt/psotify',
      packages = ['psotify', 'psotify/protocol'],
     )
