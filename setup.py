#!/usr/bin/env python3
"""
CDN检测工具 - 安装脚本
"""

from setuptools import setup, find_packages
import os

# 读取requirements.txt
with open('requirements.txt') as f:
    requirements = f.read().splitlines()

# 读取README.md
with open('Readme.md', encoding='utf-8') as f:
    long_description = f.read()

# 确保数据目录存在
os.makedirs('data/cdn', exist_ok=True)
os.makedirs('data/geoip', exist_ok=True)
os.makedirs('log', exist_ok=True)

setup(
    name='cdn_check',
    version='0.1.0',
    description='CDN检测工具 - 一个插件化的网络情报分析框架',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='CDN检测工具',
    author_email='example@example.com',
    url='https://github.com/example/cdn_check',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'cdn_check=cdn_check.cli:cli',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    python_requires='>=3.8',
) 