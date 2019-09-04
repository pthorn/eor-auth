import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

requires = [
    'passlib >= 1.7.1',
    'eor-settings'
]

setup(
    name='eor-auth',
    version='2.0.0',
    description='An authentication library',
    long_description='',
    classifiers=[
        "Programming Language :: Python",
    ],
    author='p.thorn.ru@gmail.com',
    author_email='p.thorn.ru@gmail.com',
    url='https://github.com/pthorn/eor-auth',
    keywords='web wsgi bfg pylons pyramid',
    packages=find_packages('.', exclude=['test*']),
    tests_require=['nose2'],
    test_suite="nose2.collector.collector",
    include_package_data=True,
    zip_safe=True,
    install_requires=requires,
)
