from setuptools import find_packages, setup
setup(
    name='enc_util',
    packages=find_packages(include=['enc_util']),
    version='0.0.5',
    description='Encryption helper',
    author='GamerZoli#9976',
    license='MIT',
	install_requires=['pycryptodomex'],
)