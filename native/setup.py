from setuptools import Extension, setup
setup(name="traffic-native", version="1.0.0", ext_modules=[Extension("traffic_native", ["normalize.cpp"], language="c++")])
