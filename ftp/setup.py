from distutils.core import setup, Extension

setup(name='ftp_driver',
      version='1.0',
      description='ftp_driver',
      ext_modules=[Extension('ftp_driver', sources=['ftp_driver.c'])])