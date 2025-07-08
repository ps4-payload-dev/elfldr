# ps4-payload-elfldr
This is an ELF loader for PS4 systems that have been jailbroken using the
[remote_lua_loader][lua]. The ELF loader supports dynamic linking with SPRX
files and automatic symbol resolution at runtime, and payloads are executed
in seperate processes.

## Building
Assuming you have the [ps4-payload-sdk][sdk] installed on a Debian-flavored
operating system, ps4-payload-elfldr can be compiled using the following
set of commands:

```console
john@localhost:ps4-payload-elfldr$ sudo apt-get install xxd
john@localhost:ps4-payload-elfldr$ export PS4_PAYLOAD_SDK=/opt/ps4-payload-sdk
john@localhost:ps4-payload-elfldr$ make
```

## Deployment
To run ps4-payload-elfldr, first launch a kernel exploit for your PS4 firmware
version, and send over bin_loader.lua (which also supports ruddementary ELF files).
Below is a bash script that automates this process with the lapse exploit.

```bash
#!/usr/bin/env bash

PS4_HOST=ps4

SEND_LUA=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/send_lua.py
LAPSE=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/lapse.lua
BIN_LOADER=https://raw.githubusercontent.com/shahrilnet/remote_lua_loader/refs/heads/main/payloads/bin_loader.lua

wget -qO- $LAPSE      | python3 <(wget -qO- $SEND_LUA) $PS4_HOST 9026 /dev/stdin
wget -qO- $BIN_LOADER | python3 <(wget -qO- $SEND_LUA) $PS4_HOST 9026 /dev/stdin
```

Then, deploy the ELF loader as follows:
```console
john@localhost:ps4-payload-elfldr$ export PS4_HOST=ps4
john@localhost:ps4-payload-elfldr$ export PS4_PORT=9020
john@localhost:ps4-payload-elfldr$ make test
```

## Reporting Bugs
If you encounter problems with ps4-payload-elfldr, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
ps4-payload-elfldr is licensed under the GPLv3+.

[lua]: https://github.com/shahrilnet/remote_lua_loader
[sdk]: https://github.com/ps4-payload-dev/sdk
[issues]: https://github.com/ps4-payload-dev/elfldr/issues/new
