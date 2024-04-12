# Setup

In order to use Pangea Vault plugin it's necessary to set some variables in `lemur.conf.py` file. By default it's located on `~/.lemur/lemur.conf.py`
These variables are Vault domain and its auth token. Unlike Pangea SDK in this case it's necessary to set the full Vault service URL, that's why it has `https://vault.` as prefix in the next example.
To add this variables just append these next 2 lines to the end of the config file. Then it's necessary to restart lemur to reload this config.

```
PANGEA_VAULT_DOMAIN = "https://vault.<pangea_domain>"
PANGEA_VAULT_AUTH_TOKEN = <your_token>
```