# Notifly
Notifly is a DNS middleware which is able to accept [DNS NOTIFY](https://www.ietf.org/rfc/rfc1996.txt) events.
Those events are used to hook into the PowerDNS [JSON-API](https://doc.powerdns.com/authoritative/http-api/index.html) and configurable endpoints as long as they accept JSON over HTTPS.

## PowerDNS 
PowerDNS fabricates very fine products. They work together smoothly with all sorts of components, usually via JSON-APIs or pieces of Lua script. We use the Authoritative nameserver JSON-API in order to perform DNSSEC related actions like rectify, key {generation, enabling, disabling, removal}. Something we don't use yet (but will soon) is the [dnsdist](https://dnsdist.org/) [JSON-API](https://dnsdist.org/guides/webserver.html?highlight=api) wich enables our middleware to perform all sorts of actions, like whitelist IP addresses and change rules and behavior on the fly (as notifications are coming in).

## Notifly flow diagram
![alt text](/docs/notifly_flow.png "Custom Flow")
