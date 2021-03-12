from setuptools import setup

setup(
    name='wireguard',
    version='0.1',
    py_modules=['wireguard'],
    install_requires=[
        'click',
        'phabricator',
        # 'pyyaml',
        'ruamel.yaml'
    ],
    entry_points='''
        [console_scripts]
        wireguard=wireguard:cli
    ''',
)
