%global         sum Software Factory command line client

Name:           python-sfmanager
Version:        0.1
Release:        1%{?dist}
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

%prep
%autosetup -n %{name}-%{version}

%build
export PBR_VERSION=%{version}
%{__python2} setup.py build

%install
export PBR_VERSION=%{version}
%{__python2} setup.py install --skip-build --root %{buildroot}

%check
nosetests -v

%files -n python2-sfmanager
%{python2_sitelib}/*
%{_bindir}/*

%changelog
* Tue Feb 23 2017 Fabien Boucher <fboucher@redhat.com> - 0.1-1
- Initial packaging
