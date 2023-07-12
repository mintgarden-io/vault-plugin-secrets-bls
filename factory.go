package vault_plugin_secrets_bls

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	dataKeyPath       = "path"
	dataKeyDest       = "dest"
	dataKeyData       = "data"
	dataKeyPublicKey  = "public_key"
	dataKeyPrivateKey = "private_key"
	dataKeyType       = "key_type"
	dataKeySignature  = "signature"
)

const (
	privKeyMaterial = "key_material"
	privKeyType     = "key_type"
	extraData       = "extra"
)

func Factory(ctx context.Context,
	conf *logical.BackendConfig) (logical.Backend, error) {

	b := &backend{}

	backend := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"*",
			},
		},

		Paths: []*framework.Path{
			{
				Pattern: `sign/(?P<path>.*)`,

				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
					dataKeyData: {
						Type:        framework.TypeString,
						Description: "Data to sign.",
						Required:    true,
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: handleSign,
					},
				},

				ExistenceCheck: handleExistenceCheck,

				HelpSynopsis:    "Sign data with BLS key",
				HelpDescription: "",
			},
			{
				Pattern: `move/(?P<path>.*)`,
				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
					dataKeyDest: {
						Type:        framework.TypeString,
						Description: "New location of the secret.",
					},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{
						Callback: handleMove,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: handleMove,
					},
				},
				ExistenceCheck:  handleExistenceCheck,
				HelpSynopsis:    "Move to other path",
				HelpDescription: "",
			},
			{
				Pattern: `new/(?P<path>.*)`,

				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
					dataKeyType: {
						Type: framework.TypeString,
						Description: "Key type. Supported types: " +
							"chia",
						Required: true,
						AllowedValues: []interface{}{
							keyTypeChiaStr},
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{
						Callback: handleNewRandomKey,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: handleNewRandomKey,
					},
				},

				ExistenceCheck: handleExistenceCheck,

				HelpSynopsis:    "Create a new random key",
				HelpDescription: "",
			},
			{
				Pattern: `import/(?P<path>.*)`,

				Fields: map[string]*framework.FieldSchema{
					dataKeyPath: {
						Type:        framework.TypeString,
						Description: "Location of the key.",
					},
					dataKeyType: {
						Type: framework.TypeString,
						Description: "Key type. Supported types: " +
							"chia",
						Required: true,
						AllowedValues: []interface{}{
							keyTypeChiaStr},
					},
					dataKeyPrivateKey: {
						Type:        framework.TypeString,
						Description: "Hex encoded private key material.",
						Required:    true,
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{
						Callback: handleImport,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: handleImport,
					},
				},

				ExistenceCheck: handleExistenceCheck,

				HelpSynopsis:    "Import private key",
				HelpDescription: "",
			},
			{
				Pattern: `keys/(?P<path>.*)`,

				Fields: map[string]*framework.FieldSchema{
					"path": {
						Type:        framework.TypeString,
						Description: "Location of the secret.",
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: getReadHandler(false),
					},
					logical.CreateOperation: &framework.PathOperation{
						Callback: handleWrite,
					},
					logical.UpdateOperation: &framework.PathOperation{
						Callback: handleWrite,
					},
					logical.DeleteOperation: &framework.PathOperation{
						Callback: handleDelete,
					},
					logical.ListOperation: &framework.PathOperation{
						Callback: handleList,
					},
				},

				ExistenceCheck: handleExistenceCheck,

				HelpSynopsis:    strings.TrimSpace(backendHelpSynopsis),
				HelpDescription: strings.TrimSpace(backendHelpDescription),
			},
			{
				Pattern: `private/(?P<path>.*)`,

				Fields: map[string]*framework.FieldSchema{
					"path": {
						Type:        framework.TypeString,
						Description: "Location of the key.",
					},
				},

				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{
						Callback: getReadHandler(true),
					},
				},

				ExistenceCheck: handleExistenceCheck,

				HelpSynopsis:    strings.TrimSpace(backendHelpSynopsis),
				HelpDescription: strings.TrimSpace(backendHelpDescription),
			},
		},
		Secrets: []*framework.Secret{
			{
				Type:  "kv",
				Renew: getReadHandler(false),
				Revoke: func(ctx context.Context, req *logical.Request,
					data *framework.FieldData) (*logical.Response, error) {
					// This is a no-op
					return nil, nil
				},
			},
		},
	}

	if conf == nil {
		return nil, fmt.Errorf("Configuation passed into backend is nil")
	}
	_ = backend.Setup(ctx, conf)
	b.Backend = backend

	return b, nil
}

const backendHelp = `
The backend handle operations on BLS12-381 keys.
The keys are encrypted/decrypted by Vault: they are never stored
unencrypted in the backend and the backend never has an opportunity to
see the unencrypted value.
`

const backendHelpSynopsis = `
The BLS backend generates or imports private keys for Chia, allowing you to sign messages with these keys.
`

const backendHelpDescription = `
The BLS backend generates or imports private keys for Chia.
`
