# Vault Plugin: BLS Secrets Backend

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault). This plugin provides initial BLS12-381 key storage and signing capabilities for [Chia](https://github.com/Chia-Network/chia-blockchain).

## Status

**This library has not yet been audited. Use at your own risk.**

## Build plugin

```shell
cd cmd/vault-plugin-secrets-bls
go build
```

## Install plugin

```shell
cd <path_to_vault_plugins_dir>
rm vault-plugin-secrets-bls
# copy binary plugin to vault's plugins directory
cp <path_to_vault_plugin_secrets_bls>/cmd/vault-plugin-secrets-bls/vault-plugin-secrets-bls ./
# get sha265 of plugin binary
openssl dgst -sha256 vault-plugin-secrets-bls
# register plugin with vault
vault plugin register -sha256=<checksum from previous step> vault-plugin-secrets-bls
# if plugin was registered earlier, reload it.
vault plugin reload -plugin=vault-plugin-secrets-bls
```

## Enable secret engine

```shell
vault secrets enable -path=chiakeys vault-plugin-secrets-bls
```

## Use of plugin

```shell
# Generate new random key.
# key_type may be "chia"
vault write chiakeys/new/key1 key_type=chia
# Generate new random key annotated with some metadata.
vault write chiakeys/new/key2 key_type=chia extra1=value1 extra2=value2

# List keys
vault list chiakeys/keys
# Keys
# ----
# key1
# key2

# Read key data
vault read chiakeys/keys/key2
# Key           Value
# ---           -----
# extra1         value1
# extra2         value2
# key_type       bls
# public_key     acc2b01c1c8f8ccc2c54656b5dce63b552f31ff507672563a8d1af3c075750504f7c8c38e6390934764aba837c65611a

# Get key data with private key
vault read chiakeys/private/key2
# Key           Value
# ---           -----
# extra1         value1
# extra2         value2
# key_type       bls
# private_key    62f20a27126ff05f364e0093b2099cec32f32e1be27ef017b2e9e859efbc62c7
# public_key     acc2b01c1c8f8ccc2c54656b5dce63b552f31ff507672563a8d1af3c075750504f7c8c38e6390934764aba837c65611a

# Move key2 to old_keys/key3
vault write chiakeys/move/key2 dest=chiakeys/keys/old_keys/key3

# Sign data with key.
# Fobls key data should be a hex representation of little endian encoded int.
# For ethereum key it should be a hex encoded 32-bytes hash.
vault read chiakeys/sign/key1 \
  data=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# Key          Value
# ---          -----
# data         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# signature    955f3bc3c19b19d8dfebc5be6822145af2a35cadd696e71fbd40449bd3e670b39d8283396a03bedb5ffdd24dcccfb55910aadf8339f68d26c9eae4f15cff14c4d7109cca625b5fa56d4b94c852d8584f84ab476514ba2c27b2b2467c340fd9b5

# Import new private key into vault
vault write chiakeys/import/key4 \
  key_type=bls \
  private_key=68662115c4ac948f2280f451a7a906a9b601831d0bb478a13d2be19d9f999297

# Delete key
vault delete chiakeys/keys/old_keys/key3
```

## iden3/vault-plugin-secrets-iden3 License

This project is based on [iden3/vault-plugin-secrets-iden3](https://github.com/iden3/vault-plugin-secrets-iden3), licensed under [Apache 2.0](https://github.com/iden3/vault-plugin-secrets-iden3/blob/main/LICENSE).
