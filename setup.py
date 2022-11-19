from setuptools import setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name = 'python-rmap',
    description='Automated enumeration for red teamers',
    license = 'gpl-3.0',
    author = "syspuke",
    author_email='syspuke@pm.me',
    url='https://github.com/syspuke/rmap',
    version = '0.2.0',
    packages = ['rmap'],
    entry_points = {
        'console_scripts': [
            'rmap = rmap.main:main'
        ]
    },
    python_requires='>=3.6',
    install_requires=required,
    )