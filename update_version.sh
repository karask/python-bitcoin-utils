pip uninstall -y bitcoin-utils
python setup.py sdist bdist_wheel
pip install dist/bitcoin_utils-0.8.3.tar.gz
