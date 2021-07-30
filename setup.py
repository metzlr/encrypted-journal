from setuptools import setup, find_packages

setup(
    name='encrypted-journal',
    version='0.0.1',
    packages=find_packages(),
    install_requires=[
        'click >= 8.0.1',
        'cryptography >= 3.2',
        'python-dotenv >= 0.18, <=0.19'
    ],
    include_package_data=True,
    python_requires='>=3.8',
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "Operating System :: OS Independent",
    ],
    entry_points={
        'console_scripts': ['ejournal=journal.cli:cli']
    },
)
