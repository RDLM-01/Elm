Summary: wrapper library to make eToken NG-OTP work with LinOTP Management GUI
Name: liblinotpetwrapper
Version: 0.1
Release: 1
License: AGPLv3, (c) LSE Leading Security Experts GmbH
Packager:  linotp@lsexperts.de
Group: Library/Security
Requires: pkiclient 
BuildRoot: /var/tmp/%{name}-buildroot
URL: http://www.lsexperts.de
Source: liblinotpetwrapper-0.1.tgz
Vendor: LSE Leading Security Experts GmbH

%description
LSE LinOTP is a flexible OTP authentication solution.
To enroll eToken NG OTP with the Management Clients of LinOTP, 
you need the Aladdin/SafeNet PKIClient and this wrapper library.
%prep
if [ -d ~/rpmbuild/SOURCES/%{name}-%{version} ]; then  rm -fr ~/rpmbuild/SOURCES/%{name}-%{version}; fi
mkdir ~/rpmbuild/SOURCES/%{name}-%{version}
cp -r . ~/rpmbuild/SOURCES/%{name}-%{version}
#mv  ~/rpmbuild/SOURCES/%{name}-%{version}/%{name} ~/rpmbuild/SOURCES/%{name}-%{version}/%{name}-%{version}
#tar -zcf ~/rpmbuild/SOURCES/liblinotpetwrapper.tgz ~/rpmbuild/SOURCES/%{name}-%{version}
%setup 

%build
echo "Starting building the stuff..."
ls
make clean
make
echo "Done."

%install
mkdir -p $RPM_BUILD_ROOT/usr/local/lib
cp liblinotpetwrapper.so.0.1 $RPM_BUILD_ROOT/usr/local/lib/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
#%doc README License_GPL.txt biomaildb
/usr/local/lib/liblinotpetwrapper.so.0.1

%post
ln -s /usr/local/lib/liblinotpetwrapper.so.0.1 /usr/local/lib/liblinotpetwrapper.so.0
ln -s /usr/local/lib/liblinotpetwrapper.so.0.1 /usr/local/lib/liblinotpetwrapper.so
ldconfig

%changelog

