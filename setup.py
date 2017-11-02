from distutils.core import setup

setup(
    name='derlite',
    version='0.2.0',

    description='Lightweight, pythonic DER/BER encoder/decoder',

    package_dir={'': 'src'},
    py_modules=[ 'derlite' ],

    author='Wim Lewis',
    author_email='wiml@hhhh.org',
    url='https://github.com/wiml/derlite',

    license='MIT',

    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
)

