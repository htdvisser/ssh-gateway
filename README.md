# SSH Gateway

An SSH gateway acts as some kind of forward proxy for SSH servers. This one allows you to set access and authentication for several upstream servers.

## Usage

1. Configure the server by setting up the `data` folder (see below)
2. Start the server by executing `ssh-gateway`
3. Connect to the sever with `ssh -p 2222 foo@localhost`

## Configuration

The `data` folder (location can be changed with the `DATA` environment variable) contains the configuration of the SSH gateway.

- `server` contains SSH host keys for the server. You can use `make host_keys` to generate them.
- `upstreams/foo` contains configuration for the `foo` upstream server:
  - `authorized_keys_*` files can be used to give public keys of users that can access that server
  - `config.yml` contains host/port/user config (see below)
  - `id_*` files can be used to give private keys to use with that server
  - `known_host_*` files can be used to give known host keys for that server

Example `data` folder structure:

```
data
├── server
│   ├── ssh_host_dsa_key
│   ├── ssh_host_dsa_key.pub
│   ├── ...
│   ├── ssh_host_rsa_key
│   └── ssh_host_rsa_key.pub
├── upstreams
│   ├── foo
│   │   ├── authorized_keys_alice -> ../../users/authorized_keys_alice
│   │   ├── config.yml
│   │   └── known_host_keys
│   └── bar
│       ├── authorized_keys_bob -> ../../users/authorized_keys_bob
│       ├── config.yml
│       ├── id_rsa
│       └── known_host_keys
└── users
    ├── authorized_keys_alice
    └── authorized_keys_bob
```

Example upstream `config.yml`:

```yml
host: foobar.com
port: 22 # (this is default)
user: root # (this is default)
password: hunter2 # (not recommended; use id_* files instead)
```
