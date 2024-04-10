from secrets import token_hex
from lemur.common.fields import ArrowDateTime
from lemur.users.models import User


def test_create_authority(app):
    from lemur.plugins.lemur_pangea_vault.plugin import PangeaVaultIssuerPlugin

    plugin = PangeaVaultIssuerPlugin()
    options = {
        "name": f"ca_pangea_vault_plugin_{token_hex(8)}",
        'country': 'US',
        'description': 'test',
        'first_serial': 1,
        'organizational_unit': 'Operations',
        'location': 'Los Gatos',
        'state': 'California',
        'organization': 'Netflix',
        'sensitivity': 'medium',
        'signing_algorithm': 'sha256WithRSA',
        'key_type': 'RSA2048',
        'owner': 'secure@example.com',
        'validity_end': ArrowDateTime("2044-02-20T15:31:36.774882+00:00"),
        'common_name': 'AcommonName',
        'validity_start': ArrowDateTime("2024-02-20T15:31:36.774882+00:00"),
        'type': 'root',
        'validity_years': 20,
        'creator': User(username="lemur")
    }

    plugin.create_authority(options=options)
