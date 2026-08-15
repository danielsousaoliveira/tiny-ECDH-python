from pathlib import Path
import re

from setuptools import find_packages, setup


version_text = Path("tiny_ecdh/_version.py").read_text()
version = re.search(r'__version__ = "([^"]+)"', version_text).group(1)

setup(
    name="tiny-ecdh-python",
    version=version,
    description="Educational ECDH implementation for the NIST B-163 curve",
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    url="https://github.com/danielsousaoliveira/tiny-ECDH-python",
    author="tiny-ECDH-python contributors",
    packages=find_packages(),
    python_requires=">=3.9,<3.13",
    install_requires=["numpy>=1.24"],
    include_package_data=True,
)
