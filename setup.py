#!/usr/bin/env python3
"""
LanX - Serverless LAN Chat Application
Setup script for global installation
"""

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='lanx-chat',
    version='1.1.0',
    description='Serverless LAN chat application with multi-layered encryption',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='LanX Team',
    author_email='lanx@example.com',
    url='https://github.com/lanx/lanx-chat',
    py_modules=['lanx'],
    entry_points={
        'console_scripts': [
            'lanx=lanx:main',
        ],
    },
    install_requires=[
        'flask>=2.0.0',
        'cryptography>=3.0.0',
    ],
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
            'black>=21.0',
            'flake8>=3.9',
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Communications :: Chat',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
        'Operating System :: Android',
        'Environment :: Console',
        'Environment :: Web Environment',
    ],
    keywords='chat lan p2p encryption secure messaging',
    project_urls={
        'Bug Reports': 'https://github.com/lanx/lanx-chat/issues',
        'Source': 'https://github.com/lanx/lanx-chat',
    },
)
