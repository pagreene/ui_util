from setuptools import setup, find_packages


def main():
    setup(name='auth_tools',
          description='Authentication tools for indralab UIs.',
          author='Patrick Greene',
          author_email='patrick_greene@hms.harvard.edu',
          url='http://github.com/indralab/ui_util',
          packages=find_packages(),
          install_requires=['flask-jwt-extended', 'flask'],
          include_package_data=True)


if __name__ == '__main__':
    main()
