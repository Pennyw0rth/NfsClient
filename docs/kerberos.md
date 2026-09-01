# Kerberos development setup

This procedure configures the authorized Debian target `192.168.108.140` as
the KDC and NFS server for realm `NFS.TEST`. It creates a keytab-only client
principal named `nfsclient@NFS.TEST`. Run commands one block at a time and stop
if a validation command fails.

Do not copy a keytab or credential cache into the pyNfsClient repository.

## 1. Configure names on the workstation

Add the target's canonical NFS service name:

```console
echo '192.168.108.140 nfs4.nfs.test nfs4' | sudo tee -a /etc/hosts
getent hosts nfs4.nfs.test
```

The last command must resolve `nfs4.nfs.test` to `192.168.108.140`.

## 2. Connect to the Debian target

```console
ssh debian@192.168.108.140
sudo -i
```

Use the SSH password interactively. Do not place it in a script or this
repository.

## 3. Install the server packages

```console
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y nfs-kernel-server krb5-kdc krb5-admin-server krb5-user
hostnamectl set-hostname nfs4.nfs.test
grep -q 'nfs4.nfs.test' /etc/hosts || echo '127.0.1.1 nfs4.nfs.test nfs4' >> /etc/hosts
hostname --fqdn
```

The final command must print `nfs4.nfs.test`.

## 4. Configure the Kerberos realm

Write `/etc/krb5.conf`:

```console
cp -a /etc/krb5.conf /etc/krb5.conf.pynfsclient.bak
tee /etc/krb5.conf >/dev/null <<'EOF'
[libdefaults]
    default_realm = NFS.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true

[realms]
    NFS.TEST = {
        kdc = nfs4.nfs.test
        admin_server = nfs4.nfs.test
    }

[domain_realm]
    .nfs.test = NFS.TEST
    nfs.test = NFS.TEST
EOF
```

Write `/etc/krb5kdc/kdc.conf`:

```console
cp -a /etc/krb5kdc/kdc.conf /etc/krb5kdc/kdc.conf.pynfsclient.bak
tee /etc/krb5kdc/kdc.conf >/dev/null <<'EOF'
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    NFS.TEST = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = FILE:/etc/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        default_principal_flags = +preauth
    }
EOF
```

Allow the local administrator principal:

```console
printf 'admin/admin@NFS.TEST *\n' > /etc/krb5kdc/kadm5.acl
```

Create the realm only if its database does not already exist:

```console
test -f /var/lib/krb5kdc/principal || kdb5_util create -s -r NFS.TEST
```

The command prompts for a KDC database master password. Store that password in
the normal system secret store, not in this repository.

Start and verify the KDC:

```console
systemctl enable --now krb5-kdc krb5-admin-server
systemctl --no-pager --full status krb5-kdc krb5-admin-server
kadmin.local -q 'listprincs'
```

## 5. Create the NFS service principal

Create the principal before exporting it to a keytab:

```console
kadmin.local -q 'listprincs' | grep -Fxq 'nfs/nfs4.nfs.test@NFS.TEST' || kadmin.local -q 'addprinc -randkey nfs/nfs4.nfs.test@NFS.TEST'
kadmin.local -q 'getprinc nfs/nfs4.nfs.test@NFS.TEST'
kadmin.local -q 'ktadd -k /etc/krb5.keytab -norandkey nfs/nfs4.nfs.test@NFS.TEST'
klist -kte /etc/krb5.keytab
```

The keytab listing must contain `nfs/nfs4.nfs.test@NFS.TEST`.

## 6. Create the client principal and keytab

The earlier `ktadd -norandkey` failure occurs when the principal has not first
been created, or when the command is run against the wrong realm. Use these
commands in this order:

```console
kadmin.local -q 'listprincs' | grep -Fxq 'nfsclient@NFS.TEST' || kadmin.local -q 'addprinc -randkey nfsclient@NFS.TEST'
kadmin.local -q 'getprinc nfsclient@NFS.TEST'
install -d -m 0700 /root
rm -f /root/nfsclient-user.keytab
kadmin.local -q 'ktadd -k /root/nfsclient-user.keytab -norandkey nfsclient@NFS.TEST'
test -s /root/nfsclient-user.keytab
klist -kte /root/nfsclient-user.keytab
```

If `getprinc` shows the principal but `ktadd` still fails, check the exact realm
and KDC database before retrying:

```console
kadmin.local -q 'getprinc nfsclient@NFS.TEST'
kadmin.local -q 'getprinc nfs/nfs4.nfs.test@NFS.TEST'
ls -l /var/lib/krb5kdc/principal* /etc/krb5kdc/stash
journalctl -u krb5-kdc -n 50 --no-pager
```

Do not omit `-norandkey`: omitting it rotates the principal key and can
invalidate previously issued keytabs.

## 7. Configure the NFS export

```console
install -d -m 1777 /var/nfs/pynfsclient
cp -a /etc/nfs.conf /etc/nfs.conf.pynfsclient.bak
cp -a /etc/exports /etc/exports.pynfsclient.bak
```

Ensure `/etc/nfs.conf` contains:

```ini
[nfsd]
vers3 = y
vers4 = y
vers4.0 = y
vers4.1 = y
vers4.2 = y
```

Replace `/etc/exports` with the isolated development export:

```console
printf '/var/nfs *(rw,sync,insecure,fsid=0,sec=krb5p:krb5i:krb5:sys:none,no_subtree_check,root_squash)\n' > /etc/exports
exportfs -rav
systemctl enable --now nfs-server
systemctl restart nfs-server
exportfs -v
ss -ltnp 'sport = :2049'
```

The final command must show a TCP listener on port 2049. Port 111 may remain
available for NFSv3, but it is not used by any NFSv4 client.

## 8. Copy the client keytab safely

Still on the server:

```console
install -o debian -g debian -m 0600 /root/nfsclient-user.keytab /home/debian/nfsclient-user.keytab
exit
```

Back on the workstation:

```console
install -d -m 0700 "$HOME/.config/pynfsclient"
scp debian@192.168.108.140:/home/debian/nfsclient-user.keytab "$HOME/.config/pynfsclient/nfsclient-user.keytab"
chmod 0600 "$HOME/.config/pynfsclient/nfsclient-user.keytab"
ssh debian@192.168.108.140 'rm -f /home/debian/nfsclient-user.keytab'
klist -kte "$HOME/.config/pynfsclient/nfsclient-user.keytab"
```

## 9. Obtain and verify credentials

Install a Kerberos client locally and create a user-scoped realm configuration:

```console
sudo apt-get install -y krb5-user
install -d -m 0700 "$HOME/.config/pynfsclient"
tee "$HOME/.config/pynfsclient/krb5.conf" >/dev/null <<'EOF'
[libdefaults]
    default_realm = NFS.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    forwardable = true

[realms]
    NFS.TEST = {
        kdc = nfs4.nfs.test
        admin_server = nfs4.nfs.test
    }

[domain_realm]
    .nfs.test = NFS.TEST
    nfs.test = NFS.TEST
EOF
export KRB5_CONFIG="$HOME/.config/pynfsclient/krb5.conf"
install -d -m 0700 "$HOME/.cache/pynfsclient"
export KRB5CCNAME="FILE:$HOME/.cache/pynfsclient/krb5cc"
```

Keep `KRB5_CONFIG` and `KRB5CCNAME` set in each shell used for pyNfsClient or
NetExec. pyNfsClient deliberately does not guess a platform-specific default
cache location. Then obtain and inspect the tickets:

```console
kdestroy 2>/dev/null || true
kinit -kt "$HOME/.config/pynfsclient/nfsclient-user.keytab" nfsclient@NFS.TEST
kvno nfs/nfs4.nfs.test@NFS.TEST
klist -ef
```

`klist` must show both the TGT and the NFS service ticket. A service-principal
mismatch usually means the client used the IP address as the Kerberos hostname;
use `nfs4.nfs.test` or pass that exact hostname/SPN in the credentials.

## 10. Verify pyNfsClient

From outside the repository's tracked files:

```console
python -c 'from pyNfsClient import discover_minor_versions; print(discover_minor_versions("192.168.108.140"))'
```

The configured target should report `(2, 1, 0)`. Then configure
each raw client with the current credential cache:

```python
from pyNfsClient import NFSv40, NFSv41, NFSv42
from pyNfsClient.kerberos import KerberosInitiator
from pyNfsClient.nfs4_const import NFS_PROGRAM, NFS_V4, OP_GETFH
from pyNfsClient.rpcsec_gss import RPCSECGSSAuth

credentials = {
    "realm": "NFS.TEST",
    "username": "nfsclient",
    "hostname": "nfs4.nfs.test",
    "kdc_host": "192.168.108.140",
}

for client_class in (NFSv40, NFSv41, NFSv42):
    client = client_class("192.168.108.140")
    client.connect()
    try:
        initiator = KerberosInitiator(client.host, credentials)
        client.auth = RPCSECGSSAuth.establish(client, NFS_PROGRAM, NFS_V4, initiator, "krb5i")
        response = client.compound((client.putrootfh_op(), client.getfh_op()), tag=b"kerberos-root")
        print(client_class.__name__, len(client.operation_result(response, OP_GETFH)))
    finally:
        client.disconnect()
```

Change `"krb5i"` to `"krb5"` or `"krb5p"` to select authentication-only or
privacy service. To use the keytab without a cache, add these fields to
`credentials`:

```python
"keytab": "/home/user/.config/pynfsclient/nfsclient-user.keytab",
"use_cache": False,
```
