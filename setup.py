from setuptools import setup, find_packages

setup(
    name='vulnpredict',
    version='0.1.0',
    description='Predictive Vulnerability Intelligence Tool',
    author='VulnPredict Contributors',
    packages=find_packages(),
    install_requires=[
        'requests',
        'pandas',
        'scikit-learn',
        'joblib',
        'astroid',
        'bandit',
        'click',
        'fastapi',
        'uvicorn',
        'testresources',
        'pytest',
    ],
    entry_points={
        'console_scripts': [
            'vulnpredict=vulnpredict.cli:main',
        ],
    },
    python_requires='>=3.8',
) 