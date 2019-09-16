from setuptools import setup, find_packages


def main():
    setup(name='indralab_web_templates',
          description='Jinja templates and macros for indralab UIs',
          author_email='klas_karis@hms.harvard.edu',
          url='http://github.com/indralab/ui_util',
          packages=find_packages(),
          install_requires=['flask', 'jinja2'],
          include_package_data=True)


if __name__ == '__main__':
    main()
