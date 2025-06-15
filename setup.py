from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="sigstrike",
    rust_extensions=[
        RustExtension(
            "sigstrike._sigstrike",
            binding=Binding.PyO3,
            debug=False,
            features=["python"],
        )
    ],
    packages=["sigstrike", ],
    zip_safe=False,
    package_dir={"sigstrike": "sigstrike"},
    package_data={"sigstrike": ["py.typed"]},
)
