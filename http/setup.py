from distutils.core import setup, Extension

setup(name='http_driver',
      version='1.0',
      description='http_driver',
      ext_modules=[Extension('http_driver', sources=['http_driver.c'])])