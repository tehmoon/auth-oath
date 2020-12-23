## Auth-oath

Auth-oath is a simple server/client architecture that validates TOPT pins based on a database.

It is using `oath-toolkit` which is widely available on linux/osx.

### Features:

  - Plug and play for OpenVPN
  - Retain succesful pin for 1 day so you can save it locally
  - Easy database JSON format
  - client/server through unix socket
  - Totp 30 sec/sha512/8 digits
  - Keys in base32

### Examples:

Example database:

```
[
  { "user": "blih",
    "key": "5YVZEIH5DNSA7SYPZ5KA===="
  }
]
```

To start the server -- `root`:

```
./auth-oathd -config ./config.json -socket /tmp/blih.sock
```

Authorize clients -- `openvpn`:

```
username=blih password=12345678 ./auth-oath -socket /tmp/blih.sock
```

Then copy this into your totp software and select 8 digits/sha512.


### Help:

Auth-oathd:

```
Usage of ./auth-oathd:
  -config string
    	Path to the user json file
  -group string
    	Set group name on the socket file
  -socket string
    	Path to the socket file
  -user string
    	Set user name on the socket file
```

Auth-oath:

```
Usage of ./auth-oath:
  -socket string
    	Path to the socket file
```

### Todo:

server:
- CRUD user endpoint
- remove base32

client:
- CRUD user API
- qrencode display

### Future:

If this project is useful for people I will make the following features available:

  - Add hashed password for users so it is `password | pin`
  - Set expiration time per user
  - Native TOTP
  - Add CLI to manage database
  - Reload database
  - add --daemon flag
  - add --log flag
  - encrypt client/server for extra security
