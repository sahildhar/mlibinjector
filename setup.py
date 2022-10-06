from setuptools import setup

setup(
	name='mlibinjector',
	version='1.0',
	author='Sahil Dhar (@0x401)',
	install_requires=[
	"lief == 0.12.2",
	"termcolor"
	],
	packages=['mlibinjector'],
	entry_points={
		'console_scripts':[
			"mlibinjector = mlibinjector.run:main"
		]

	},
	include_package_data=True,
	zip_safe=False
)
