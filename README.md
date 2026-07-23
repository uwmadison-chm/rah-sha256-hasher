# rah-sha256-hasher
An example handler for redcap-alert-handler

This takes a salted hash of a value that arrives in a REDCap alert and writes the digest back into the record through the REDCap API. Hashing isn't something REDCap can do on its own, so it's a small but real example of the kind of work you'd hand off to rah -- an alert comes in, a handler does something REDCap can't, and a record gets updated.

It's mainly here as a worked example: a handler you can wire all the way up in a test project to prove the parts fit together, and a starting point other people can copy.

## Configuration

Point a route at `rah-sha256-hasher:hash_field`:

```toml
[routes.hasher]
handler = "rah-sha256-hasher:hash_field"
redcap_info_file = "/etc/rah/example-project-info.toml"
redcap_id_field = "record_id"
hashed_value_field = "value_hash"
```

The handler reads these rah configuration values:

* `redcap_info_file` (string) The path to a TOML file with the REDCap `url`, `token`, and hashing `salt`
* `redcap_id_field` (string) The field that holds the project's record identifier
* `hashed_value_field` (string) The field the digest gets written to

The `redcap_info_file` is kept out of the route config on purpose, so the API token and salt never land in the same file as everything else. It's a TOML file with three keys:

```toml
url = "https://redcap.wisc.edu/api/"
token = "your-project-api-token"
salt = "a-long-random-string-you-keep-secret"
```

The `salt` keys the hash. Without it -- a plain hash of the value -- an MRN or any other low-entropy value can be walked back from the digest by hashing candidates until one matches, so the digest wouldn't really de-identify anything. Keep the salt secret and don't change it, or the same value will start producing a different digest. There's no salt in the route config or a default: leave it out of the info file and the handler stops with a PermanentError rather than writing a reversible hash.

Generate one with Python and paste it in:

```
python -c "import secrets; print(secrets.token_hex(32))"
```

## What it does

Each alert is one record and one value to hash. rah's alerts can carry whatever body you want; this handler expects TOML with two string keys:

```toml
id = "{record_id}"
value = "{value_to_hash}"
```

`id` is the record to update and `value` is the string to hash. Fill those braces in from REDCap's piping when you set up the alert. Any other keys in the body are ignored.

Once it reads `id` and `value`, it will:

* Read `redcap_info_file` to get the API address, token, and salt
* Record the message id in a sqlite database in the route's state directory, so a message that's already been processed is skipped instead of hashed in again
* Take the HMAC-SHA-256 of `value` keyed on the salt -- UTF-8 bytes, lowercase hex
* Connect to the REDCap API and import the digest into `hashed_value_field` for record `id`
* If that succeeds, mark the message complete in the database and return
* If the connection to REDCap times out, raise TransientError so the message retries
* If the import fails for any other reason, or the info file doesn't get us into REDCap, raise PermanentError
* For any other unexpected exception, raise PermanentError

A blank `value` is treated as a misfire -- an alert that fired on an empty field -- and raises PermanentError, since hashing it would write the same constant digest to the record and a retry wouldn't change that.

The message id goes into the database *before* the import, not after. rah abandons a handler that times out rather than killing it, so the first attempt can still be running when a retry starts. Writing the id down first is what lets a retry see the message and skip it. The idempotency here is on the message, not the record: two separate alerts naming the same record are two separate writes. That's fine for this handler, because the digest is a pure function of the value -- importing the same record's same value twice just writes the same thing again.

## Running the tests

From this directory, `uv sync` and then `uv run pytest`.
