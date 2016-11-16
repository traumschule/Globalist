# Globalist
Idea: distributed githubless repository sharing. Yes, this is the official home ;-)

Globalist is an attempt to ease the distribution of git repos, away from central points of failure.

Globalist stands for "Global List" and aims at replacing any EtherPads of more than transient value.

It grew out of [this](http://j7652k4sod2azfu6.onion/p/cloudflare-tor) discussion. EtherPad is nice but has its limitations.

Globalist is also meant to evolve into an experimental distributed asynchronous wiki facility, for example when the central wiki of a conference succumbs to a DDos on the 0th day ;-)

Nodes can come and go, and network topology only depends on the peers entries in the nodes' config files. Changes that are merged by one's peers propagate by diffusion.

## Usage

For each shared repo, Globalist will create one .onion service.

```
[network]
peers = <comma-separated list of onion domain names, with or without the suffix .onion>
```