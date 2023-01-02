from distutils.core import setup, Extension

setup(name='userp',
      version='1.0',
      description='user',
      ext_modules=[Extension('userp', sources=['userp.c'])])