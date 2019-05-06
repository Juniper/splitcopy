from setuptools import setup, find_packages

setup(
    name="splitcopy",
    version='1.0.0',
    url="https://github.com/Juniper/splitcopy",
    author="Chris Jenn",
    author_email="jnpr-community-netdev@juniper.net",
    license="Apache 2.0",
    description="splits file, tranfers chunks to host, recombines chunks",
    long_description=open('README.md').read(),
    py_modules=['splitcopy'],
    python_requires='>=3.4',
    install_requires=[
        'junos-eznc>=2.2.1',
    ],
    entry_points={
        'console_scripts': [
            'splitcopy=splitcopy:main',
        ],
    },
)
