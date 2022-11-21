from setuptools import setup
from rmap import __version__

setup(
    name = 'python-rmap',
    description='Automated enumeration for red teamers',
    license = 'gpl-3.0',
    author = "syspuke",
    author_email='syspuke@pm.me',
    url='https://github.com/syspuke/rmap',
    version = __version__,
    packages = ['rmap'],
    entry_points = {
        'console_scripts': [
            'rmap = rmap.main:main'
        ]
    },
    python_requires='>=3.6',
    )