# CheckMK integration

`notify_nuncio.py` is a CheckMK notification plugin that forwards notifications
to Nuncio for enrichment, with an automatic fallback that delivers the raw alert
straight to an [Apprise](https://github.com/caronc/apprise) gateway if Nuncio is
unreachable. Because CheckMK RAW has no notification spooling, that in-plugin
fallback is what makes it safe to route notifications through Nuncio: an Nuncio
outage degrades to the plain alert instead of dropping it.

## Install

Copy the plugin into your site's local notifications directory (CheckMK scans
it automatically) and make it executable:

```bash
cp notify_nuncio.py \
   /omd/sites/<site>/local/share/check_mk/notifications/notify_nuncio
chmod +x /omd/sites/<site>/local/share/check_mk/notifications/notify_nuncio
```

The file name (without extension) is the method name CheckMK shows in the UI.

## Configure a notification rule

In **Setup → Notifications**, add a rule with the notification method
`notify_nuncio` and up to three parameters:

| Parameter | Meaning | Example |
|-----------|---------|---------|
| 1 | Nuncio base URL | `http://nuncio:8095` |
| 2 | Nuncio ingest token (sent as `X-Auth-Token`) | *(your `NUNCIO_INGEST_TOKEN`)* |
| 3 | Apprise fallback URL (raw alert on Nuncio failure) | `http://apprise:8000/notify/checkmk` |

Parameter 1 defaults to `http://nuncio:8095` if omitted. Parameters 2 and 3 are
optional; without a fallback URL the plugin simply reports failure to CheckMK
if Nuncio is unreachable.

## What gets sent

The plugin forwards every `NOTIFY_*` environment variable CheckMK provides to
`POST /ingest/checkmk` as a JSON object. Nuncio's `checkmk` source adapter
derives a stable idempotency key (host / service / problem id / notification
type / number) and a structured alert from those fields.
