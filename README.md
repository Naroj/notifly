# Notifly
Notifly is a DNS middleware which is able to accept [DNS NOTIFY](https://www.ietf.org/rfc/rfc1996.txt) events.
Those events are used to hook into the PowerDNS [JSON-API] (https://doc.powerdns.com/authoritative/http-api/index.html) and custom configurable endpoints.

## PowerDNS 
PowerDNS has very fine products to work together with all sorts of components. In our scenario we use the JSON-API specifically in order to perform DNSSEC related actions like rectify, key-generation and probably more soon. Something we don't use yet (but will soon) is the [dnsdist] (https://dnsdist.org/) [JSON-API] (https://dnsdist.org/guides/webserver.html?highlight=api) wich enables our middleware to perform all sorts of actions, like whitelist IP addresses and change rules and behavior on the fly (as notifications are coming in).

![alt text](/docs/notifly_flow.png "Custom flow")
