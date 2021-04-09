import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="sliver-py",
    version="0.0.1",
    author="moloch",
    author_email="875022+moloch--@users.noreply.github.com",
    description="Sliver gRPC client library.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/moloch--/sliver-py",
    project_urls={
        "Bug Tracker": "https://github.com/moloch--/sliver-py/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
    include_package_data=True
)