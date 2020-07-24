# A tool to build DNS blackhole zone files

Creates blackhole zone files by downloading and parsing the blocklist files
assembled by [The Firebog](https://firebog.net).  Blocklists may be assembled
based on the category of blocklist and on the quality of the available
blocklists.

The output can be formatted for:

* [Unbound](https://nlnetlabs.nl/projects/unbound/about/)
* [BIND](https://www.isc.org/bind/)
* simple text list

---

# Unbound
First generate a blackhole zone file like this:

```
blackhole -f unbound -o /path/to/blackhole.zone
```

then import the newly created blackhole zone file by including it in your
`unbound.conf` file by adding something like this:

```
# blackhole domains
include: "/usr/local/etc/unbound/blackhole.zone"
```

---

# BIND

_Not implemented yet_

---

# Text

Simply run the following commmand:

```
blackhole
```

[src]: https://github.com/pauldokas/blackhole
