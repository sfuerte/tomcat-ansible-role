# tomcat-ansible-role

[![Build Status](https://travis-ci.org/zaxos/tomcat-ansible-role.svg?branch=master)](https://travis-ci.org/zaxos/tomcat-ansible-role)

Ansible role to install and configure Apache Tomcat on your target host. Based on `zaxos.tomcat-ansible-role`. Only stable Tomcat versions with no announced [End of Life](https://en.wikipedia.org/wiki/Apache_Tomcat#History) (EoL) are supported, i.e.

- 8.5
- 9.0

## Installation

```sh
ansible-galaxy install git+https://github.com/sfuerte/tomcat-ansible-role
```

## Requirements

- Ansible: this role was developed and tested with [maintained](https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html#release-status) versions of Ansible, backwards compatibility is not guaranteed;
- supported Java;
- the Apache Portable Runtime (APR) library (`libapr1`);
- JNI wrappers for APR used by Tomcat (`libtcnative`), see more [here](https://tomcat.apache.org/tomcat-9.0-doc/apr.html);
- OpenSSL libraries;
- SELinux disabled.

## Platforms

```yaml
CentOS / RedHat:
    - 7
    - 8
Debian:
    - 9 (stretch)
    - 10 (buster)
Fedora:
    - 31
    - 32
Ubuntu:
    - 18.04 LTS (bionic)
    - 20.04 LTS (focal)
```

## Role Variables

Available variables are listed below along with default values, see `defaults/main.yml` for details.

Package and installation settings:

- `tomcat_state: present` - accepted values are `absent` and `present`;
- `tomcat_force_install: false`
- `tomcat_version: 9.0.37`
- `tomcat_downloadURL: https://archive.apache.org/dist/tomcat/tomcat-{{ tomcat_version.split('.')[0] }}/v{{ tomcat_version }}/bin/apache-tomcat-{{ tomcat_version }}.tar.gz`
- `tomcat_user: tomcat`
- `tomcat_group: tomcat`
- `tomcat_runtime_user: "{{ tomcat_user }}"` - for running a web application under a different user, in that case make sure it is part of `{{ tomcat_group }}` group;
- `tomcat_group_create: true`
- `tomcat_user_create: true`
- `system_base: /opt` - base directory where distribution package(s) will be installed to;
- `catalina_home: "{{ system_base }}/tomcat"` - defines the location of symlink name to the Tomcat distribution with its libs, default modules and default settings, as well as Tomcat user home directory. **Important**, it should be treated as a standard of truth and remain unmodified nor changed;
- `catalina_base: "/var/lib/tomcat"` - defines the location of a specific implementation of a Tomcat server, its configuration, logs and web applications; all changes or additions to your configuration should take place there; see more at [this StackOverflow reply](https://stackoverflow.com/questions/3090398/tomcat-catalina-base-and-catalina-home-variables) and [official documentation](https://tomcat.apache.org/tomcat-9.0-doc/RUNNING.txt);
- `tomcat_dir_mode: 0750` - `base` and `logs` directory permissions;
- `tomcat_file_mode: 0640` - for files under `base` only;
- `tomcat_delete_old: false` - whether to delete any other installed distribution except of the specified version; matching directories by `{{ system_base }}/apache-tomcat-*`;
- `tomcat_demo_delete: true`

Systemd service settings:

- `tomcat_service_enabled: true`
- `tomcat_service_name: "tomcat"`
- `tomcat_pid: "{{ catalina_base }}/tomcat.pid"`
- `tomcat_start: false`
- `tomcat_start_log: "{{ catalina_base }}/logs/tomcat-start.log"`

Runtime settings:

- `tomcat_listen_address: 0.0.0.0`
- `tomcat_port_http: 8080`
- `tomcat_port_https: 8443`
- `tomcat_port_ajp: -1` - can be disabled by setting to `-1`;
- `tomcat_port_debug: -1`
- `tomcat_port_shutdown: -1`
- `tomcat_users` - list of Tomcat users to be created, see the example below for the expected format;
- `tomcat_server_listeners` - list of enabled LifeCycle Listeners, see more at [official documentation](https://tomcat.apache.org/tomcat-9.0-doc/config/listeners.html):

  ```sh
  - "org.apache.catalina.core.AprLifecycleListener"
  - "org.apache.catalina.core.JreMemoryLeakPreventionListener"
  - "org.apache.catalina.core.ThreadLocalLeakPreventionListener"
  - "org.apache.catalina.mbeans.GlobalResourcesLifecycleListener"
  - "org.apache.catalina.security.SecurityListener"
  - "org.apache.catalina.storeconfig.StoreConfigLifecycleListener"
  - "org.apache.catalina.startup.VersionLoggerListener"
  ```

- `tomcat_server_listeners_conf` - LifeCycle Listener configuration:

  ```sh
  AprLifecycleListener: 'SSLEngine="on"'
  JreMemoryLeakPreventionListener: 'appContextProtection="true"'
  ```

- `tomcat_https_redirect: false`
- `tomcat_ssl_generate_cert: false`
- `tomcat_ssl_certificate`:

  ```sh
  file: "{{ catalina_base }}/conf/ssl/localhost.crt"
  key: "{{ catalina_base }}/conf/ssl/localhost.key"
  ```

- `tls_protocols`: TLSv1.3 and TLSv1.2;
- `tls_cipher_suites` - see <https://www.ssllabs.com/ssltest> and <https://github.com/dev-sec/ssl-baseline> for details:

  ```sh
  # TLS 1.3 cipher suites
  TLS_AES_256_GCM_SHA384
  # TLS 1.2 cipher suites
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ```

- `catalina_opts`:

  ```sh
  -Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE=true
  -Dorg.apache.catalina.connector.RECYCLE_FACADES=true
  -Dorg.apache.tomcat.util.http.ServerCookie.ALWAYS_ADD_EXPIRES=true
  ```

- `java_options`:

  ```sh
  -server
  -Xms1g
  -Xmx1g
  -XX:MetaspaceSize=256m
  -XX:MaxMetaspaceSize=256m
  -XX:+UseContainerSupport
  -XX:MaxTenuringThreshold=1
  -XX:+UseAES
  -XX:+UseCompressedOops
  -Djava.security.egd=file:/dev/./urandom
  -XX:+DisableExplicitGC
  -XX:+UnlockExperimentalVMOptions
  -XX:+UseZGC
  -Xlog:gc:file={{ catalina_base }}/logs/jvm_gc.log:utctime,pid,level,tags:filecount=5,filesize=1024
  -XX:+PrintClassHistogram
  -XX:+HeapDumpOnOutOfMemoryError
  -XX:HeapDumpPath={{ catalina_base }}/logs/jvm_heapdump.hprof
  ```

In case the default templates don't suit your needs, you can use your own custom templates by changing the following variables:

- `tomcat_template_systemd_service: "tomcat.service.j2"`
- `tomcat_template_server: "tomcat-server-{{ '.'.join(tomcat_version.split('.')[:2]) }}.xml.j2"`
- `tomcat_template_users: "tomcat-users-{{ '.'.join(tomcat_version.split('.')[:2]) }}.xml.j2"`

Uninstall default parameters:

- `tomcat_uninstall_create_backup: true` - whether to create a backup tar archive at system base folder before deletion;
- `tomcat_uninstall_remove_all: false` - to override the below values and delete everything related to Tomcat installation;
- `tomcat_uninstall_remove_group: true`
- `tomcat_uninstall_remove_user: true`

Optional variables (by default undefined):

- `tomcat_group_gid: 500`
- `tomcat_user_uid: 500` - to set custom UID and/or GID for homogeneity across multiple servers.

## Returned values

The following values are "returned" via `set_fact` for consecutive re-use:

- `catalina_home`
- `tomcat_version`

## Dependencies

None, i.e. no any other role will be installed along with this one.

## Security

The following steps have been taken to secure and harden the service:

- a test installation has been verified with [Inspec](https://github.com/inspec/inspec) [tomcat-baseline](https://github.com/T-Systems-MMS/tomcat-baseline) profile;
- a dedicated non-root system account is used for the web server;
- Java (`JAVA_OPTS`) and Tomcat (`CATALINA_OPTS`) options have been modified as per above;
- a number of extra listeners have been enabled, including `JreMemoryLeakPrevention`, `ThreadLocalLeakPrevention` and Security Listeners;
- GZIP compression is enabled;
- trace and `xpoweredBy` are disabled;
- connection limit is set to 4000;
- `StuckThreadDetectionValve` is set to 60 seconds for preventing potential DoS by limiting request processing time;
- crawler valve is set to context and host aware, to ensure that crawlers are associated with a single session;
- disabled server information as well as custom message and/or stack trace when reporting errors;
- logging pattern expanded with full [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp and other extra fields;
- `httpHeaderSecurity` filter has been configured for the following HTTP headers:

    ```sh
    Strict-Transport-Security: max-age=15552000; includeSubDomains - set on HTTPS only
    X-Content-Type-Options: nosniff
    X-Frame-Options: SAMEORIGIN
    X-XSS-Protection: 1; mode=block
    ```

- added `HttpOnly` and `Secure` flags to cookies;
- if HTTP to HTTPS redirection is needed, uncomment `security-constraint` section at the bottom of Tomcat's `conf/web.xml`file;
- disabled server version and `XPoweredBy` information in HTTP headers;
- HTTP/2, including `h2c`, has been enabled;
- HTTPS is limited to TLS v1.2 and 1.3 with strong ciphers only;
- default HTTP headers have been modified as per above;
- strick order of ciphers is enforced;
- request logging has been enabled in [expanded NCSA](https://en.wikipedia.org/wiki/Common_Log_Format) format;

## Example Playbooks

A playbook example:

```yaml
- hosts: servers
  become: true
  vars:
    tomcat_version: 9.0.37

    tomcat_users:
      - username: "tomcat"
        password: "t3mpp@ssw0rd"
        roles: "tomcat,admin,manager,manager-gui"
      - username: "exampleuser"
        password: "us3rp@ssw0rd"
        roles: "tomcat"
  roles:
    - role: zaxos.tomcat-ansible-role
```

An example of including role in a task:

```yaml
- name: Tomcat setup
  block:
    - name: install - `tomcat-ansible-role` role on Master Host
      become: false
      # command: ansible-galaxy install zaxos.tomcat-ansible-role
      command: ansible-galaxy install git+https://github.com/sfuerte/tomcat-ansible-role
      delegate_to: localhost
      run_once: true

    - name: including role
      include_role:
        name: tomcat-ansible-role
      vars:
        catalina_base: "{{ tomcat.base | default('/opt/tomcat-app') }}"
        tomcat_service_name: "my-tomcat-app"
        tomcat_ssl_generate_cert: "{{ tomcat.ssl_generate_cert | default(true) }}"
        tomcat_start: true
        java_options: "{{ java_opts +' '+ tomcat.java_opts | default('') }}"
  when: web_server | lower == "tomcat"
```
