# rsrcon

Rust implementation of [RCON](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol)

Supports multi packet responses

## install
cargo install --path .

## env variables
RCON_PASSWORD

RCON_ADDRESS (ip:port)

note, the address must be a port. You can find the ip of a domain with `host {domain}` on linux
## usage
```
Usage: rsrcon [OPTIONS] [CMD]...

Arguments:
  [CMD]...  

Options:
  -p, --password <PASSWORD>  
  -a, --address <ADDRESS>    
  -h, --help                 Print help
  -V, --version              Print version
```

## examples
```
$ rsrcon list
There are 0 of a max of 20 players online: 

$ RCON_PASSWORD=password RCON_ADDRESS=ip:port rsrcon list
There are 0 of a max of 20 players online: 
```