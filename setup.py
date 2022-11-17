from setuptools import setup

setup(
    name = 'python-rmap',
    license = 'gpl-3.0',
    author = "syspuke",
    author_email='syspuke@pm.me',
    version = '0.1',
    packages = ['rmap'],
    entry_points = {
        'console_scripts': [
            'rmap = rmap.rmap:main'
        ]
    })