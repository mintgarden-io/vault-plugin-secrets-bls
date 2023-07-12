package vault_plugin_secrets_bls

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/wrapping"
	"github.com/hashicorp/vault/sdk/logical"
	blst "github.com/supranational/blst/bindings/go"
)

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

type backend struct {
	*framework.Backend
}

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_")

func handleMove(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	key := data.Get(dataKeyPath).(string)
	destKey := data.Get(dataKeyDest).(string)

	destKey = strings.TrimPrefix(destKey, "/")

	wantPrefix := path.Join(req.MountPoint, "keys") + "/"
	if !strings.HasPrefix(destKey, wantPrefix) {
		return nil, fmt.Errorf(
			"destination key path must have prefix %v", wantPrefix)
	}

	destKey = strings.TrimPrefix(destKey, wantPrefix)

	// Read the path
	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:      destKey,
		Value:    out.Value,
		SealWrap: out.SealWrap,
	})
	if err != nil {
		return nil, fmt.Errorf("write failed: %v", err)
	}

	err = req.Storage.Delete(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("delete failed: %v", err)
	}

	return nil, nil
}

func handleExistenceCheck(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (bool, error) {
	key := data.Get("path").(string)

	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %v", err)
	}

	return out != nil, nil
}

func handleNewRandomKey(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	keyPath := data.Get(dataKeyPath).(string)
	if keyPath == "" {
		return nil, errors.New("key path is empty")
	}

	// Read the path
	out, err := req.Storage.Get(ctx, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	if out != nil {
		return logical.ErrorResponse("key already exists"), nil
	}

	keyTp, err := newKeyTypeFromString(data.Get(dataKeyType).(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var privKey string
	switch keyTp {
	case keyTypeChia:
		privKey = randomBlsKey()
	default:
		return logical.ErrorResponse("unsupported key type"), nil
	}
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	extra := make(map[string]interface{})
	var obj = map[string]interface{}{
		privKeyMaterial: privKey,
		privKeyType:     keyTp.String(),
		extraData:       extra,
	}

	for k, v := range req.Data {
		if k == dataKeyType {
			continue
		}
		extra[k] = v
	}

	entry, err := logical.StorageEntryJSON(keyPath, obj)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func handleImport(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	keyPath := data.Get(dataKeyPath).(string)
	if keyPath == "" {
		return nil, errors.New("key path is empty")
	}

	// Read the path
	out, err := req.Storage.Get(ctx, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	if out != nil {
		return logical.ErrorResponse("key already exists"), nil
	}

	keyTp, err := newKeyTypeFromString(data.Get(dataKeyType).(string))
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	keyMaterial, ok := data.Get(dataKeyPrivateKey).(string)
	if !ok {
		return nil, errors.New("private key is not found")
	}

	var privKey string
	switch keyTp {
	case keyTypeChia:
		privKey, err = normalizeBlsKey(keyMaterial)
	default:
		return logical.ErrorResponse("unsupported key type"), nil
	}
	if err != nil {
		return logical.ErrorResponse(
			fmt.Sprintf("key check failed: %v", err.Error())), nil
	}

	extra := make(map[string]interface{})
	for k, v := range req.Data {
		if k == dataKeyType || k == dataKeyPrivateKey {
			continue
		}
		extra[k] = v
	}

	var obj = map[string]interface{}{
		privKeyMaterial: privKey,
		privKeyType:     keyTp.String(),
		extraData:       extra,
	}

	entry, err := logical.StorageEntryJSON(keyPath, obj)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func handleSign(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	key := data.Get(dataKeyPath).(string)
	dataToSign := data.Get(dataKeyData).(string)

	// Read the path
	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}

	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}

	pkStr, keyTp, err := extractKeyAndType(rawData)
	if err != nil {
		return nil, err
	}

	var signature string
	switch keyTp {
	case keyTypeChia:
		signature, err = signWithBls(pkStr, dataToSign)
	default:
		return logical.ErrorResponse("unsupported key type"), nil
	}
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			dataKeySignature: signature,
			dataKeyData:      dataToSign,
		},
	}

	return resp, nil
}

func getReadHandler(showPrivate bool) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request,
		data *framework.FieldData) (*logical.Response, error) {

		key := data.Get("path").(string)

		// Read the path
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read failed: %v", err)
		}

		// Fast-path the no data case
		if out == nil {
			return nil, nil
		}

		// Decode the data
		var rawData map[string]interface{}

		if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
			return nil, fmt.Errorf("json decoding failed: %v", err)
		}

		privKeyStr, keyTp, err := extractKeyAndType(rawData)
		if err != nil {
			return nil, fmt.Errorf("unable to extract key and type: %v", err)
		}

		outData, ok := rawData[extraData].(map[string]interface{})
		if !ok {
			outData = make(map[string]interface{})
		}

		switch keyTp {
		case keyTypeChia:
			outData[dataKeyPublicKey], err = blsPubKeyFromHex(privKeyStr)
		default:
			return logical.ErrorResponse("unsupported key type"), nil
		}
		if err != nil {
			return nil, err
		}

		outData[privKeyType] = keyTp.String()

		if showPrivate {
			outData[dataKeyPrivateKey] = rawData[privKeyMaterial]
		}

		resp := &logical.Response{Data: outData}

		// Ensure seal wrapping is carried through if the response is
		// response-wrapped
		if out.SealWrap {
			if resp.WrapInfo == nil {
				resp.WrapInfo = &wrapping.ResponseWrapInfo{}
			}
			resp.WrapInfo.SealWrap = out.SealWrap
		}

		return resp, nil
	}
}

func handleWrite(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	key := data.Get("path").(string)
	if key == "" {
		return logical.ErrorResponse("missing path"), nil
	}

	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if out == nil {
		return logical.ErrorResponse("key not found"), nil
	}

	var rawData map[string]interface{}

	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}

	// Check that some fields are given
	if len(req.Data) == 0 {
		delete(rawData, extraData)
		return logical.ErrorResponse("missing data fields"), nil
	} else {
		rawData[extraData] = req.Data
	}

	entry, err := logical.StorageEntryJSON(key, rawData)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to write: %v", err)
	}

	return nil, nil
}

func handleDelete(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	key := data.Get("path").(string)

	// Delete the key at the request path
	if err := req.Storage.Delete(ctx, key); err != nil {
		return nil, err
	}

	return nil, nil
}

func handleList(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	// Right now we only handle directories, so ensure it ends with /; however,
	// some physical backends may not handle the "/" case properly, so only add
	// it if we're not listing the root
	path := data.Get("path").(string)
	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// List the keys at the prefix given by the request
	keys, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	// Generate the response
	return logical.ListResponse(keys), nil
}

type keyType uint8

func (t keyType) String() string {
	switch t {
	case keyTypeChia:
		return keyTypeChiaStr
	default:
		return "unknown"
	}
}

const (
	keyTypeUnknown keyType = iota
	keyTypeChia
)

const (
	keyTypeChiaStr = "chia"
)

func newKeyTypeFromString(tp string) (keyType, error) {
	switch tp {
	case keyTypeChiaStr:
		return keyTypeChia, nil
	default:
		return keyTypeUnknown, errors.New("unknown key type")
	}
}

// hex representation of random bls key
func randomBlsKey() string {
	var ikm [32]byte
	_, _ = rand.Read(ikm[:])
	sk := blst.KeyGen(ikm[:])

	return hex.EncodeToString(sk.Serialize())
}

func decodeBlsPrivKey(keyStr string) (*blst.SecretKey, error) {
	key := new(blst.SecretKey)
	privKeyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return key, err
	}

	if len(privKeyBytes) != 32 {
		return key, errors.New("private key data length is incorrect")
	}

	key.Deserialize(privKeyBytes)
	return key, nil
}

func blsPubKeyFromHex(keyStr string) (string, error) {
	key, err := decodeBlsPrivKey(keyStr)
	if err != nil {
		return "", err
	}

	pubKey := new(PublicKey).From(key)

	return hex.EncodeToString(pubKey.Compress()), nil
}

func extractKeyAndType(data map[string]interface{}) (string, keyType, error) {
	pkStr, ok := data[privKeyMaterial].(string)
	if !ok {
		return "", keyTypeUnknown, fmt.Errorf("key material not found")
	}

	keyTpStr, ok := data[privKeyType].(string)
	if !ok {
		return "", keyTypeUnknown, fmt.Errorf("key type not found")
	}

	keyTp, err := newKeyTypeFromString(keyTpStr)
	if err != nil {
		return "", keyTypeUnknown, fmt.Errorf("invalid key type: %v", err)
	}

	return pkStr, keyTp, nil
}

func signWithBls(privKeyHex string, dataToSign string) (string, error) {
	privKey, err := decodeBlsPrivKey(privKeyHex)
	if err != nil {
		return "", err
	}

	message, err := hex.DecodeString(dataToSign)
	if err != nil {
		return "", fmt.Errorf(
			"unable to decode data to sign from hex string to bytes: %v", err)
	}

	pk := new(PublicKey).From(privKey)
	messageWithPrependedPk := append(pk.Compress(), message...)
	sig := new(Signature).Sign(privKey, messageWithPrependedPk, dst)

	if !sig.Verify(true, pk, true, messageWithPrependedPk, dst) {
		return "", fmt.Errorf("unable to sign data with bls key: %v", err)
	}

	return hex.EncodeToString(sig.Compress()), err
}

// take key hex string, try to convert it to BLS private key, check for
// errors and convert to hex string back
func normalizeBlsKey(keyHex string) (string, error) {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("unable to decode BJJ key from hex: %v", err)
	}
	if len(keyBytes) != blst.BLST_SCALAR_BYTES {
		return "", fmt.Errorf("BLS key data length is incorrect")
	}
	return hex.EncodeToString(keyBytes), nil
}
