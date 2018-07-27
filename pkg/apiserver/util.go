package apiserver

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"strings"

	"k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "kubevirt.io/containerized-data-importer/pkg/common"
)

const (
	// upload proxy generated
	apiSecretName = "cdi-api-private"

	// upload proxy generated
	uploadProxySecretName = "cdi-proxy-private"

	// uploadProxy Public key
	apiPublicKeyConfigMap = "cdi-api-public"

	// uploadProxy Public key
	uploadProxyPublicKeyConfigMap = "cdi-proxy-public"
)

func RecordApiPublicKey(client *kubernetes.Clientset, publicKey *rsa.PublicKey) error {
	return setPublicKeyConfigMap(client, publicKey, apiPublicKeyConfigMap)
}

//func RecordApiPrivateKey(client *kubernetes.Clientset, privateKey *rsa.PrivateKey) error {
//	return setPrivateKeySecret(client, privateKey, apiSecretName)
//}

func RecordUploadProxyPublicKey(client *kubernetes.Clientset, publicKey *rsa.PublicKey) error {
	return setPublicKeyConfigMap(client, publicKey, uploadProxyPublicKeyConfigMap)
}

func RecordUploadProxyPrivateKey(client *kubernetes.Clientset, privateKey *rsa.PrivateKey) error {
	return setPrivateKeySecret(client, privateKey, uploadProxySecretName)
}

func GetApiPublicKey(client *kubernetes.Clientset) (*rsa.PublicKey, bool, error) {
	return getPublicKey(client, apiPublicKeyConfigMap)
}

func GetUploadProxyPublicKey(client *kubernetes.Clientset) (*rsa.PublicKey, bool, error) {
	return getPublicKey(client, uploadProxyPublicKeyConfigMap)
}

func GetUploadProxyPrivateKey(client *kubernetes.Clientset) (*rsa.PrivateKey, bool, error) {
	return getPrivateSecret(client, uploadProxySecretName)
}

//func GetApiPrivateKey(client *kubernetes.Clientset) (*rsa.PrivateKey, bool, error) {
//	return getPrivateSecret(client, apiSecretName)
//}

func GetNamespace() string {
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}
	return metav1.NamespaceSystem
}

func getConfigMap(client *kubernetes.Clientset, configMap string) (*v1.ConfigMap, bool, error) {
	namespace := GetNamespace()

	config, err := client.CoreV1().ConfigMaps(namespace).Get(configMap, metav1.GetOptions{})

	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, false, nil
		} else {
			return nil, false, err
		}
	}

	return config, true, nil
}

func encodePublicKey(key *rsa.PublicKey) string {
	bytes := x509.MarshalPKCS1PublicKey(key)
	return base64.StdEncoding.EncodeToString(bytes)
}

func decodePublicKey(encodedKey string) (*rsa.PublicKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PublicKey(bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func getPublicKey(client *kubernetes.Clientset, configMap string) (*rsa.PublicKey, bool, error) {
	config, exists, err := getConfigMap(client, configMap)
	if err != nil {
		return nil, false, err
	}

	if !exists {
		return nil, false, nil
	}

	publicKeyEncoded, ok := config.Data["publicKey"]
	if !ok {
		return nil, false, nil
	}

	key, err := decodePublicKey(publicKeyEncoded)

	return key, true, err
}

func setPublicKeyConfigMap(client *kubernetes.Clientset, publicKey *rsa.PublicKey, configMap string) error {
	publicKeyEncoded := encodePublicKey(publicKey)
	namespace := GetNamespace()

	config, exists, err := getConfigMap(client, configMap)
	if err != nil {
		return err
	}

	if exists {
		// Update
		config.Data["publicKey"] = publicKeyEncoded
		_, err := client.CoreV1().ConfigMaps(namespace).Update(config)
		if err != nil {
			return err
		}
	} else {
		// Create
		config := &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: configMap,
				Labels: map[string]string{
					CDI_COMPONENT_LABEL: configMap,
				},
			},
			Data: map[string]string{
				"publicKey": publicKeyEncoded,
			},
		}
		_, err := client.CoreV1().ConfigMaps(namespace).Create(config)
		if err != nil {
			return err
		}
	}
	return nil
}

func encodePrivateKey(key *rsa.PrivateKey) string {
	bytes := x509.MarshalPKCS1PrivateKey(key)
	return base64.StdEncoding.EncodeToString(bytes)
}

func decodePrivateKey(encodedKey string) (*rsa.PrivateKey, error) {
	bytes, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func getSecret(client *kubernetes.Clientset, secretName string) (*v1.Secret, bool, error) {
	namespace := GetNamespace()
	secret, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, false, nil
		} else {
			return nil, false, err
		}
	}

	return secret, true, nil
}

func getPrivateSecret(client *kubernetes.Clientset, secretName string) (*rsa.PrivateKey, bool, error) {
	secret, exists, err := getSecret(client, secretName)
	if err != nil {
		return nil, false, err
	}

	if !exists {
		return nil, false, nil
	}

	privateKeyEncoded, ok := secret.Data["privateKey"]
	if !ok {
		return nil, false, nil
	}

	key, err := decodePrivateKey(string(privateKeyEncoded))

	return key, true, err
}

func setPrivateKeySecret(client *kubernetes.Clientset, privateKey *rsa.PrivateKey, secretName string) error {
	privateKeyEncoded := encodePrivateKey(privateKey)
	namespace := GetNamespace()

	secret, exists, err := getSecret(client, secretName)
	if err != nil {
		return err
	}

	if exists {
		// Update
		secret.Data["privateKey"] = []byte(privateKeyEncoded)
		_, err := client.CoreV1().Secrets(namespace).Update(secret)
		if err != nil {
			return err
		}
	} else {
		// Create
		secret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretName,
				Labels: map[string]string{
					CDI_COMPONENT_LABEL: secretName,
				},
			},
			Data: map[string][]byte{
				"privateKey": []byte(privateKeyEncoded),
			},
		}
		_, err := client.CoreV1().Secrets(namespace).Create(secret)
		if err != nil {
			return err
		}
	}
	return nil
}
