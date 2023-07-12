package vault_plugin_secrets_bls

import (
	"context"
	"testing"

	// "strings"
	"encoding/hex"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
		BackendUUID: "test",
	}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	// Wait for the upgrade to finish
	timeout := time.After(20 * time.Second)
	ticker := time.Tick(time.Second)

	for {
		select {
		case <-timeout:
			t.Fatal("timeout expired waiting for upgrade")
		case <-ticker:
			// req := &logical.Request{
			// 	Operation: logical.ListOperation,
			// 	Path:      "keys",
			// 	Storage:   config.StorageView,
			// }

			// resp, err := b.HandleRequest(context.Background(), req)
			// if err != nil {
			// 	t.Fatalf("unable to list keys: %s", err.Error())
			// 	return nil, nil
			// }

			// if resp != nil && !resp.IsError() {
			return b, config.StorageView
			// }

			// if resp == nil || (resp.IsError() && strings.Contains(resp.Error().Error(), "Upgrading from non-versioned to versioned")) {
			// 	t.Log("waiting for upgrade to complete")
			// }
		}
	}
}

// create random key in vault and return path to it
// func newRandomBJJKey(t testing.TB, b *api.Client, kPath keyPath,
// 	extraData map[string]interface{}) {

// 	data := map[string]interface{}{
// 		"key_type": "babyjubjub",
// 	}
// 	for k, v := range extraData {
// 		data[k] = v
// 	}
// 	_, err := vaultCli.Logical().Write(kPath.new(), data)
// 	require.NoError(t, err)
// }

// func getSecretData(secret *api.Secret) map[string]interface{} {
// 	if secret == nil {
// 		panic("secret is nil")
// 	}

// 	if secret.Data == nil {
// 		panic("secret data is nil")
// 	}

// 	return secret.Data
// }

// func randomString() string {
// 	var rnd [16]byte
// 	_, err := rand.Read(rnd[:])
// 	if err != nil {
// 		panic(err)
// 	}

// 	return hex.EncodeToString(rnd[:])
// }

// // sign data with key
// func signWithKey(vaultCli *api.Client, kPath keyPath,
// 	dataToSign []byte) []byte {

// 	dataStr := hex.EncodeToString(dataToSign)
// 	data := map[string][]string{"data": {dataStr}}
// 	secret, err := vaultCli.Logical().ReadWithData(kPath.sign(), data)
// 	if err != nil {
// 		panic(err)
// 	}
// 	data2 := getSecretData(secret)
// 	sigStr, ok := data2["signature"].(string)
// 	if !ok {
// 		panic("unable to get signature from secret")
// 	}
// 	sig, err := hex.DecodeString(sigStr)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return sig
// }

// // move key under new path
// func moveKey(vaultCli *api.Client, oldPath, newPath keyPath) {
// 	data := map[string]interface{}{"dest": newPath.keys()}
// 	_, err := vaultCli.Logical().Write(oldPath.move(), data)
// 	if err != nil {
// 		panic(err)
// 	}
// }

// func dataAtPath(t testing.TB, vaultCli *api.Client,
// 	keyPath string) map[string]interface{} {

// 	secret, err := vaultCli.Logical().Read(keyPath)
// 	require.NoError(t, err)
// 	if secret == nil {
// 		return nil
// 	}
// 	return getSecretData(secret)
// }

func getKeySet(m map[string]interface{}) map[string]struct{} {
	set := make(map[string]struct{})

	for k := range m {
		set[k] = struct{}{}
	}

	return set
}

func TestBlsPlugin(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"key_type": "chia",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "new/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("create request failed, err: %s, resp %#v", err, resp)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/foo",
		Storage:   storage,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("read request failed, err: %s, resp %#v", err, resp)
	}

	publicKeyString := resp.Data["public_key"].(string)
	pubKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		t.Fatalf("failed to decode pubkey, err: %s", err)
	}
	pubKey := new(PublicKey).Uncompress(pubKeyBytes)

	data = map[string]interface{}{
		"data": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "sign/foo",
		Storage:   storage,
		Data:      data,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("sign request failed, err: %s, resp %#v", err, resp)
	}

	msg, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	msgWithPkPrepended := append(pubKeyBytes, msg...)

	signatureString := resp.Data["signature"].(string)
	signatureBytes, err := hex.DecodeString(signatureString)
	if err != nil {
		t.Fatalf("failed to decode signature, err: %s", err)
	}
	signature := new(Signature).Uncompress(signatureBytes)

	if !signature.Verify(true, pubKey, true, msgWithPkPrepended, dst) {
		t.Fatalf("failed to verify signature")
	}
}
