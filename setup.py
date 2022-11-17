from setuptools import setup

setup(
    name = 'rmap',
    version = '0.1.0',
    packages = ['rmap'],
    entry_points = {
        'console_scripts': [
            'rmap = rmap.rmap:main'
        ]
    })