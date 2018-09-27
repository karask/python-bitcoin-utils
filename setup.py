from setuptools import setup
from bitcoinutils import __version__

with open('README.rst') as readme:
    long_description = readme.read()

setup(name='bitcoin-utils',
      version=__version__,
      description='Bitcoin utility functions',
      long_description=long_description,
      author='Konstantinos Karasavvas',
      author_email='kkarasavvas@gmail.com',
      url='https://github.com/karask/python-bitcoin-utils',
      license='AGPLv3',
      packages=['bitcoinutils'],
      zip_safe=False
     )

