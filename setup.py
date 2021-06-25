from setuptools import setup, find_packages
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

setup(
   name='arbiter',
   python_requires=">3.8",
   version='0.0.1',
   packages=find_packages(),
   description='A static+dynamic vulnerability detection tool',
   long_description=open(f'{BASE_DIR}/README.md').read(),
   install_requires=[
       "angr>= 9.0.4663",
   ],
)