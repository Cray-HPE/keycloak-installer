# Copyright 2019 Cray Inc. All Rights Reserved.

Name: keycloak-crayctldeploy
License: Cray Software License Agreement
Summary: Cray Keycloak Ansible role
Group: System/Management
Version: 3.0.0
Release: %(echo ${BUILD_METADATA})
Source: %{name}-%{version}.tar.bz2
Vendor: Cray Inc.
Requires: kubernetes-crayctldeploy
Requires: sms-crayctldeploy
Requires: gitea-crayctldeploy

# Project level defines TODO: These should be defined in a central location; DST-892
%define afd /opt/cray/crayctl/ansible_framework
%define roles %{afd}/roles
%define playbooks %{afd}/customer_runbooks
%define modules %{afd}/library

%description
This is an Ansible role for the deployment of Keycloak.

%prep
%setup -q

%build

%install
install -m 755 -d %{buildroot}%{roles}/
install -m 755 -d %{buildroot}%{playbooks}/

# All roles from this project
cp -r roles/* %{buildroot}%{roles}/

# All playbooks from this project
cp -r ansible/customer_runbooks/* %{buildroot}%{playbooks}/

%clean
rm -rf %{buildroot}%{roles}/*
rm -rf %{buildroot}%{playbooks}/*

%files
%defattr(755, root, root)

%dir %{roles}
%{roles}/keycloak
%{roles}/keycloak_localize
%{roles}/keycloak-manifests

%dir %{playbooks}
%{playbooks}/keycloak-localize.yml

%changelog
