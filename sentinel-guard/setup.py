from setuptools import setup, find_packages

setup(
    name="sentinel-guard",
    version="1.0.0",
    description="Real antivirus engine with signature-based and heuristic detection",
    author="Yalazay",
    python_requires=">=3.8",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "sentinel=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
