from setuptools import setup
setup(
    name='passwordManager',
    version='0.0.1',
    entry_points={
        'console_scripts': [
            'passwordManager=passwordManager:main'
        ]
    }
)
