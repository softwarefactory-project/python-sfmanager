%global         sum Software Factory command line client

Name:           python-sfmanager
Version:        0.8.4
Release:        2%{?dist}
Summary:        %{sum}
Obsoletes:      python2-sfmanager

License:        ASL 2.0
URL:            https://softwarefactory-project.io/r/p/%{name}
Source0:        HEAD.tgz

BuildArch:      noarch

Buildrequires:  python3-devel
Buildrequires:  python3-setuptools
Buildrequires:  python3-pbr

%description
Software Factory command line client

%package -n python3-sfmanager
Summary:        %sum
Obsoletes:      python2-sfmanager

Requires:       python3-PyYAML
Requires:       python3-urllib3
Requires:       python3-crypto
Requires:       python3-prettytable
Requires:       python3-requests
Requires:       python3-GitPython

%description -n python3-sfmanager
%sum

%package doc
Summary:        Sfmanager documentation
BuildRequires:  python3-sphinx

%description doc
Sfmanager documentation

%prep
%autosetup -n %{name}-%{version}

%build
export PBR_VERSION=%{version}
%{__python3} setup.py build
sphinx-build-3 -b html -d docs/build/doctrees docs/source docs/build/html
sphinx-build-3 -b man -d docs/build/doctrees docs/source docs/build/man

%install
export PBR_VERSION=%{version}
%{__python3} setup.py install --skip-build --root %{buildroot}
install -p -D -m 644 etc/software-factory.rc %{buildroot}/%{_sysconfdir}/%{name}/software-factory.rc
mkdir -p %{buildroot}/usr/share/doc/python-sfmanager
mv docs/build/html/* %{buildroot}/usr/share/doc/python-sfmanager/
mkdir -p %{buildroot}%{_mandir}/man1
mv docs/build/man/* %{buildroot}%{_mandir}/man1

%files -n python3-sfmanager
%{python3_sitelib}/*
%exclude %{python3_sitelib}/*/tests
%{_bindir}/*
%config(noreplace) %{_sysconfdir}/*
%{_mandir}/man1/*.1.gz

%files doc
/usr/share/doc/python-sfmanager/

%changelog
* Tue Aug 16 2022 Daniel Pawlik <dpawlik@redhat.com> - 0.8.4-2
- Fix dependencies requirements

* Tue Dec 10 2019 Tristan Cacqueray <tdecacqu@redhat.com> - 0.6.0-1
- Update package to python3

* Thu Apr 12 2018 Tristan Cacqueray <tdecacqu@redhat.com> - 0.1-4
- Remove pysflib requirements

* Mon Mar 20 2017 Tristan Cacqueray <tdecacqu@redhat.com> - 0.1-3
- Add html documentation

* Mon Mar 6 2017 Matthieu Huin <mhuin@redhat.com> - 0.1-2
- Add default, global rc file

* Thu Feb 23 2017 Fabien Boucher <fboucher@redhat.com> - 0.1-1
- Initial packaging
