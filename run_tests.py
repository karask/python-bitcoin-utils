import unittest

# Create a test loader and discover tests in the 'tests' directory
loader = unittest.TestLoader()
suite = loader.discover('tests')

# Run the tests
runner = unittest.TextTestRunner()
runner.run(suite)