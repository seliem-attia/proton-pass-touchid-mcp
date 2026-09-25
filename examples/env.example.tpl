# Example template for local project variables.
# {{ pass://SHARE_ID/ITEM_ID[/FIELD] }} references a Proton Pass field.
# Render:  passx inject -i env.example.tpl -o .env      (terminal, 1x Touch ID)
#     or   the MCP tool pass_inject (reason + one named Touch ID tap)
#
# Field names with spaces or umlauts must be URL-encoded, e.g. "API Key" -> API%20Key.
# Get share/item IDs with:  passx item list "My Vault" --output json
#
# Non-secret variables are set directly:
APP_ENV=development
LOG_LEVEL=debug

# Secrets pulled from Proton Pass:
# OPENAI_API_KEY={{ pass://SHARE_ID/ITEM_ID/password }}
# DATABASE_URL={{ pass://SHARE_ID/ITEM_ID/some_custom_field }}
