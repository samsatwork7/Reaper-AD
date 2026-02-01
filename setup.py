from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="reaperad",
    version="3.0.0",
    author="Satyam Singh",
    description="Active Directory Exploitation Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/satyam-singh-cyber/reaperad",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Systems Administration :: Authentication/Directory"
    ],
    python_requires=">=3.8",
    install_requires=[
        "impacket>=0.9.24",
        "ldap3>=2.9",
        "colorama>=0.4.6"
    ],
    entry_points={
        "console_scripts": [
            "reaperad=reaperad:main",
        ],
    },
)
