
Name: xrootd-multiuser
Version: 2.0.0
Release: 1%{?dist}
Summary: Multiuser filesystem writing plugin for xrootd

Group: System Environment/Daemons
License: BSD
URL: https://github.com/opensciencegrid/xrootd-multiuser
# Generated from:
# git archive v%{version} --prefix=xrootd-multiuser-%{version}/ | gzip -7 > ~/rpmbuild/SOURCES/xrootd-multiuser-%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz

%define xrootd_current_major 5
%define xrootd_current_minor 2
%define xrootd_next_major 6

BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires: xrootd-server-libs >= 1:%{xrootd_current_major}
BuildRequires: xrootd-server-libs <  1:%{xrootd_next_major}
BuildRequires: xrootd-server-devel >= 1:%{xrootd_current_major}
BuildRequires: xrootd-server-devel <  1:%{xrootd_next_major}
BuildRequires: cmake
BuildRequires: gcc-c++
BuildRequires: libcap-devel
%{?systemd_requires}
# For %{_unitdir} macro
BuildRequires: systemd

Requires: xrootd-server >= 1:%{xrootd_current_major}.%{xrootd_current_minor}
Requires: xrootd-server <  1:%{xrootd_next_major}.0.0-1

%description
%{summary}

%prep
%setup -q

%build
%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make VERBOSE=1 %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%post
%systemd_post xrootd-privileged@.service

%preun
%systemd_preun xrootd-privileged@.service

%postun
%systemd_postun xrootd-privileged@.service

%files
%defattr(-,root,root,-)
%{_libdir}/libXrdMultiuser-*.so
%{_unitdir}/xrootd-privileged@.service
%{_sysconfdir}/xrootd/config.d/60-osg-multiuser.cfg

%changelog
* Tue Sep 14 2021 Derek Weitzel <dweitzel@unl.edu> - 2.0.0-1
- Add checksum library that saves to extended attributes
- Add multiuser.checksumonwrite option to turn on checksumming the file while it is being written.

* Fri Jun 02 2021 Derek Weitzel <dweitzel@unl.edu> - 1.1.0-1
- Add file mask on creation
- Disable POSC

* Fri May 07 2021 Derek Weitzel <dweitzel@unl.edu> - 1.0.0-1
- Wrap the OSS filesystem rather than SFS.  Available in XRootD 5.0+
- Add checksum wrapper, only available in XRootD 5.2+

* Thu May 06 2021 Carl Edquist <edquist@cs.wisc.edu> - 1.0.0-0.2.rc.2
- Update to 1.0.0 rc2 (SOFTWARE-4599)

* Tue May 04 2021 Mátyás Selmeci <matyas@cs.wisc.edu> - 1.0.0-0.1.rc.1
- Update to 1.0.0 rc1 (SOFTWARE-4599)

* Fri Mar 12 2021 Carl Edquist <edquist@cs.wisc.edu> - 0.5.0-1
- Build against xrootd 5.1 (SOFTWARE-4426)
- Refactor how username is determined to match new behavior in xrootd 5.1 (#17)
- Check for 'request.name' attribute before failing (#18)
- Obtain username from passed env when SecEntity object not passed (#19)
- Disable POSC when set in file open() (#20)

* Fri Oct 30 2020 Diego Davila <didavila@ucsd.edu> - 0.4.5-1
- Adding 60-osg-multiuser.cfg (SOFTWARE-4259)

* Thu Sep 24 2020 Diego Davila <didavila@ucsd.edu> - 0.4.4-1
- use vector resize instead of vector reserve to make it work in el8 (SOFTWARE-4257)

* Tue Jul 14 2020 Diego Davila <didavila@ucsd.edu> - 0.4.3-3
- updating XRootD adding minor version to requirements (SOFTWARE-4137)

* Fri Jun 26 2020 Diego Davila <didavila@ucsd.edu> - 0.4.3-2
- updating XRootD requirements to only the major version (SOFTWARE-4137)

* Wed Jun 10 2020 Diego Davila <didavila@ucsd.edu> - 0.4.3-1
- Adding XrootD major version to the shared file name
- building against XrootD-4.12.2 (software-4093)

* Fri Apr 24 2020 Edgar Fajardo <emfajard@ucsd.edu> - 0.4.2-8
- Rebuild against xrootd 4.12; (SOFTWARE-4063)

* Wed Oct 23 2019 Carl Edquist <edquist@cs.wisc.edu> - 0.4.2-5
- Rebuild against xrootd 4.11; add version range dependency (SOFTWARE-3830)

* Thu Jul 18 2019 Carl Edquist <edquist@cs.wisc.edu> - 0.4.2-4
- Rebuild against xrootd 4.10.0 and update versioned dependency (SOFTWARE-3697)

* Wed Apr 10 2019 Mátyás Selmeci <matyas@cs.wisc.edu> - 0.4.2-3
- Rebuild against xrootd 4.9.1 and add versioned dependency (SOFTWARE-3485)

* Wed Feb 27 2019 Carl Edquist <edquist@cs.wisc.edu> - 0.4.2-2
- Rebuild against xrootd 4.9.0 (SOFTWARE-3485)

* Wed Aug 08 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.4.2-1
- Fix chaining of sendfile requests.
- Fix potentially misleading error message.

* Sun Aug 05 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.4.1-1
- Fix errant message after GID switch.

* Mon Jul 30 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.4.0-1
- Add support for POSIX-like umask.
- Make multiuser plugin compatible with Macaroons.
- Avoid a segfault if the plugin is improperly configured.

* Sat Jul 28 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.3.1-1
- Propagate errors from underlying SFS object.

* Wed Sep 20 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 0.3-1
- Fix effective capabilities on all transfer threads.

* Wed Sep 20 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 0.2-1
- Initial packaging of the multiuser plugin.

