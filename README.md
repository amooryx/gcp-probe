<div align="center">
  <img src="./banner.svg" alt="gcp-probe" width="800">
</div>

# gcp-probe

> Red team security tool — authorized use only.

```bash
python gcp_probe.py --help
```

> **Authorized security testing only.**

## Metadata collection

`--metadata` collects the configured GCE project and instance metadata fields.
It intentionally does not request service-account OAuth access tokens, so those
credentials are not printed or written to the JSON results. Other returned
metadata can still be environment-specific; review output before sharing it.
This check only reports metadata fields that respond and does not assess the
security of the attached service account or its permissions.

**Omar Khalid** — [omareldemery.com](https://omareldemery.com)
