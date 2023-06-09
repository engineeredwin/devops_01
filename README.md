---
- name: Generate JKS Keystore and CSR
  hosts: windows_servers
  gather_facts: false
  vars_files:
    - vars.yml

  tasks:
    - name: Create JKS Keystore
      win_command: keytool -genkeypair -alias "{{ key_alias }}" -keyalg RSA -keysize 2048 -keystore "{{ keystore_path }}" -storepass "{{ keystore_password }}" -keypass "{{ key_password }}" -dname "CN={{ dn_common_name }}, OU={{ dn_organization_unit }}, O={{ dn_organization }}, L={{ dn_locality }}, ST={{ dn_state }}, C={{ dn_country }}" -validity "{{ validity_days }}"
      args:
        executable: "{{ ansible_env.JAVA_HOME }}/bin/keytool.exe"

    - name: Generate CSR
      win_command: keytool -certreq -alias "{{ key_alias }}" -file "{{ csr_path }}" -keystore "{{ keystore_path }}" -storepass "{{ keystore_password }}"
      args:
        executable: "{{ ansible_env.JAVA_HOME }}/bin/keytool.exe"
        
        
        ---
keystore_path: "C:\path\to\keystore\keystore.jks"
keystore_password: "mypassword"
key_alias: "myalias"
key_password: "mypassword"
dn_common_name: "mydomain.com"
dn_organization_unit: "Org Unit"
dn_organization: "Organization"
dn_locality: "City"
dn_state: "State"
dn_country: "Country"
validity_days: 365
csr_path: "C:\path\to\keystore\{{ ansible_hostname }}.csr"
