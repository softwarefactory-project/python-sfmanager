%global         sum Software Factory command line client

Name:           python-sfmanager
Version:        0.1
Release:        3%{?dist}
Summary:        %{sum}

License:        ASL 2.0
URL:            https://softwarefactory-project.io/r/p/%{name}
Source0:        https://github.com/redhat-cip/%{name}/archive/master.tar.gz

BuildArch:      noarch

Requires:       python2-pysflib
Requires:       PyYAML
Requires:       python2-urllib3
Requires:       python-crypto
Requires:       python-prettytable
Requires:       python-requests

Buildrequires:  python2-devel
Buildrequires:  python-setuptools
Buildrequires:  python2-pbr
Buildrequires:  python-nose
Buildrequires:  python2-mock
BuildRequires:  python2-pysflib
BuildRequires:  PyYAML
BuildRequires:  python2-urllib3
BuildRequires:  python-crypto
BuildRequires:  python-prettytable
BuildRequires:  python-requests

%description
Software Factory command line client

%package -n python2-sfmanager
Summary:        %{sum}
Requires:       python2-pysflib
Requires:       PyYAML
Requires:       python2-urllib3
Requires:       python-crypto
Requires:       python-prettytable
Requires:       python-requests

Buildrequires:  python2-devel
Buildrequires:  python-setuptools
Buildrequires:  python2-pbr
Buildrequires:  python-nose
Buildrequires:  python2-mock
BuildRequires:  python2-pysflib
BuildRequires:  PyYAML
BuildRequires:  python2-urllib3
BuildRequires:  python-crypto
BuildRequires:  python-prettytable
BuildRequires:  python-requests

%description -n python2-sfmanager
Software Factory command line client

%package doc
Summary:        Sfmanager documentation

BuildRequires:  python-sphinx

%description doc
Sfmanager documentation

%prep
%autosetup -n %{name}-%{version}

%build
export PBR_VERSION=%{version}
%{__python2} setup.py build
sphinx-build -b html -d docs/build/doctrees docs/source docs/build/html
sphinx-build -b man -d docs/build/doctrees docs/source docs/build/man

%install
export PBR_VERSION=%{version}
%{__python2} setup.py install --skip-build --root %{buildroot}
install -p -D -m 644 etc/software-factory.rc %{buildroot}/%{_sysconfdir}/%{name}/software-factory.rc
mkdir -p %{buildroot}/usr/share/doc/python-sfmanager
mv docs/build/html/* %{buildroot}/usr/share/doc/python-sfmanager/
mkdir -p %{buildroot}%{_mandir}/man1
mv docs/build/man/* %{buildroot}%{_mandir}/man1

%check
nosetests -v

%files -n python2-sfmanager
%{python2_sitelib}/*
%{_bindir}/*
%config(noreplace) %{_sysconfdir}/*
%{_mandir}/man1/*.1.gz

%files doc
/usr/share/doc/python-sfmanager/

%changelog
* Mon Mar 20 2017 Tristan Cacqueray <tdecacqu@redhat.com> - 0.1-3
- Add html documentation

* Mon Mar 6 2017 Matthieu Huin <mhuin@redhat.com> - 0.1-2
- Add default, global rc file

* Thu Feb 23 2017 Fabien Boucher <fboucher@redhat.com> - 0.1-1
- Initial packaging
