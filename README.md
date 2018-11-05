# SSH Gateway

An SSH gateway acts as some kind of forward proxy for SSH servers. This one allows you to set access and authentication for several upstream servers.

## Downloads

Release builds can be downloaded from the [tag builds](https://gitlab.com/htdvisser/ssh-gateway/pipelines?scope=tags) page, development builds from the [branch builds](https://gitlab.com/htdvisser/ssh-gateway/pipelines?scope=branches) page. Docker images are on [`registry.gitlab.com/htdvisser/ssh-gateway`](https://gitlab.com/htdvisser/ssh-gateway/container_registry).

## Usage

1. Configure the server by setting up the `data` folder (see below)
2. Start the server by executing `ssh-gateway`
3. Connect to the sever with `ssh -p 2222 foo@localhost`

## Configuration

The `data` folder (location can be changed with the `DATA` environment variable) contains the configuration of the SSH gateway.

- `server` contains global configuration:
  - `ssh_host_*` files contain SSH host keys for the server. You can use `make host_keys` to generate them.
  - `authorized_keys_*` files can be used to give public keys of users that can access **all** servers
- `upstreams/foo` contains configuration for the `foo` upstream server:
  - `authorized_keys_*` files can be used to give public keys of users that can access that server
  - `config.yml` contains host/port/user config (see below)
  - `id_*` files can be used to give private keys to use with that server
  - `known_host_*` files can be used to give known host keys for that server

Example `data` folder structure:

```
data
├── server
│   ├── authorized_keys_charlie -> ../../users/authorized_keys_charlie
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
    ├── authorized_keys_bob
    └── authorized_keys_charlie
```

Example upstream `config.yml`:

```yml
host: foobar.com
port: 22 # (this is default)
user: root # (this is default)
password: hunter2 # (not recommended; use id_* files instead)
```

## Advanced Functionality

### Environment

The SSH Gateway injects some environment variables into upstream sessions:

```
SSH_GATEWAY_USER_ADDR=ip:port
SSH_GATEWAY_USER_PUBKEY_COMMENT=name@domain.tld
SSH_GATEWAY_USER_PUBKEY_FINGERPRINT=SHA256:...
SSH_GATEWAY_USER_PUBKEY_NAME=authorized_keys_name
```

To use these, you'll need to add `AcceptEnv SSH_GATEWAY_*` to `/etc/ssh/sshd_config` on your upstreams.

### Commands

Users can execute special commands on the SSH gateway if they have access to the special "command user" (default: `gateway`, modify with `--command-user` or `$COMMAND_USER`). Don't forget to authorize their keys to the "command user" upstream (by default `./data/upstreams/gateway/`).

#### `ssh -p 2222 gateway@localhost list`

List the names of upstreams you can connect to:

```
foo bar
```

#### `ssh -p 2222 gateway@localhost config`

Generate a config for upstreams you can connect to:

```
Host foo
  HostName $SSH_HOST
  Port $SSH_PORT
  User foo

Host bar
  HostName $SSH_HOST
  Port $SSH_PORT
  User bar
```

If you have an `Include config.d/*` in your `.ssh/config`, you can update your list of networks by piping the output of the command into `sed -e 's/$SSH_HOST/localhost/g' -e 's/$SSH_PORT/2222/g' > ~/.ssh/config.d/ssh_gateway`
