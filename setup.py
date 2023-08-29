from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(here, "README.md"), encoding="utf-8") as fh:
    long_description = "\n" + fh.read()

VERSION = '0.3.5.10'
DESCRIPTION = 'Swiftly Secure your Apps'
LONG_DESCRIPTION = long_description

# Setting up
setup(
    name="swiftcrypt",
    version=VERSION,
    author="Tech Tweaks",
    author_email="tech.tweaks.contact@gmail.com",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=long_description,
    packages=find_packages(),
    install_requires=["bcrypt==4.0.1", "pyotp==2.9.0", "qrcode==7.4.2", "cryptography==41.0.3", "keyring==24.2.0"],
    keywords=['keys', 'passwords', 'crypting', 'encoding', 'secure', 'uuid'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: Microsoft :: Windows",
    ]
)

