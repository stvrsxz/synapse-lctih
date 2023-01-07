# synapse-lctih

A Little CTI Helper Synapse Rapid Power-Up.

A simple, not very smart, but useful poor man's power-up for Synapse.

**Caution**: This is experimental and always run it in a new view first.

## Installation:

From releases:

```
storm> pkg.load --raw storm> pkg.load --raw https://github.com/stvrsxz/synapse-lctih/releases/latest/download/synapse_lctih.json
```

Or clone the repo and run the following:

```
python -m synapse.tools.genpkg <lctih.yaml location> --push <your cortex telepath URL>
```

## Usage:

### Commands:

- `lctih.explore` - Given a node, pivot in and walk, pivot out and walk and in the end pivot to tags.
- `lctih.pivoting.sources` - Given a node, print the urls of possible related pivoting sources. (The prints are trading the hassle of api keys with manual work but many times it is enough)
- `lctih.update.misp.clusters` - Update the MISP galaxy threat actor cluster.

### Examples:

- `inet:fqdn=google.com | lctih.explore`
- `inet:fqdn=google.com | lctih.pivoting.sources`
    - `inet:fqdn=google.com | lctih.pivoting.sources --external`
- `lctih.update.misp.clusters`
    - `cron.add --hour 12 {lctih.update.misp.clusters}` - Add a cron every day at 12:00 pm.





