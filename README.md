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

[src]: https://github.com/pauldokas/blackhole
