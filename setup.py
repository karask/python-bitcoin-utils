from setuptools import setup
from bitcoinutils import __version__

with open("README.rst") as readme:
    long_description = readme.read()

setup(
    name="bitcoin-utils",
    version=__version__,
    description="Bitcoin utility functions",
    long_description=long_description,
    author="Konstantinos Karasavvas",
    author_email="kkarasavvas@gmail.com",
    url="https://github.com/karask/python-bitcoin-utils",
    license="MIT",
    keywords="bitcoin library utilities tools",
    install_requires=[
        "base58check>=1.0.2,<2.0",
        # Replaced ecdsa with coincurve
        "coincurve>=13.0.0",  
        "sympy>=1.2,<2.0",
        "python-bitcoinrpc>=1.0,<2.0",
        "hdwallet~=3.0",
    ],
    packages=["bitcoinutils"],
    zip_safe=False,
)