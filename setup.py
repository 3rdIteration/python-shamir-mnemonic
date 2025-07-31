from setuptools import find_packages, setup

with open("README.rst", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="shamir-mnemonic",
    version="0.3.1",
    description="SLIP-39 Shamir Mnemonics",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    author="Trezor",
    author_email="info@trezor.io",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    package_data={"shamir_mnemonic": ["wordlist.txt"]},
    python_requires=">=3.6,<4.0",
    install_requires=[
        "dataclasses; python_version<'3.7'",
    ],
    extras_require={
        "cli": ["click>=7,<9"],
    },
    entry_points={
        "console_scripts": ["shamir=shamir_mnemonic.cli:cli"],
    },
)
