package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/glog"
	"github.com/pkg/errors"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/cert/triple"

	cdiv1 "kubevirt.io/containerized-data-importer/pkg/apis/cdicontroller/v1alpha1"
	. "kubevirt.io/containerized-data-importer/pkg/common"
)

const (
	// Default port that api listens on.
	defaultPort = 8443

	// Default address api listens on.
	defaultHost = "0.0.0.0"

	// selfsigned cert secret name
	apiCertSecretName = "cdi-api-certs"

	apiMutationWebhook = "cdi-api-mutator"
	tokenMutationPath  = "/uploadtoken-mutate"

	apiServiceName = "cdi-api"

	certBytesValue        = "cert-bytes"
	keyBytesValue         = "key-bytes"
	signingCertBytesValue = "signing-cert-bytes"
)

var (
	configPath string
	masterURL  string
	verbose    string
)

type cdiAPIApp struct {
	bindAddress string
	bindPort    uint

	client *kubernetes.Clientset

	certsDirectory string

	signingCertBytes           []byte
	certBytes                  []byte
	keyBytes                   []byte
	clientCABytes              []byte
	requestHeaderClientCABytes []byte
}

func init() {
	// flags
	flag.StringVar(&configPath, "kubeconfig", os.Getenv("KUBECONFIG"), "(Optional) Overrides $KUBECONFIG")
	flag.StringVar(&masterURL, "server", "", "(Optional) URL address of a remote api server.  Do not set for local clusters.")
	flag.Parse()

	// get the verbose level so it can be passed to the importer pod
	defVerbose := fmt.Sprintf("%d", DEFAULT_VERBOSE) // note flag values are strings
	verbose = defVerbose
	// visit actual flags passed in and if passed check -v and set verbose
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "v" {
			verbose = f.Value.String()
		}
	})
	if verbose == defVerbose {
		glog.V(Vuser).Infof("Note: increase the -v level in the api deployment for more detailed logging, eg. -v=%d or -v=%d\n", Vadmin, Vdebug)
	}

}

func (app *cdiAPIApp) getClientCert() error {
	authConfigMap, err := app.client.CoreV1().ConfigMaps(metav1.NamespaceSystem).Get("extension-apiserver-authentication", metav1.GetOptions{})
	if err != nil {
		return err
	}

	clientCA, ok := authConfigMap.Data["client-ca-file"]
	if !ok {
		return errors.Errorf("client-ca-file value not found in auth config map.")
	}
	app.clientCABytes = []byte(clientCA)

	// request-header-ca-file doesn't always exist in all deployments.
	// set it if the value is set though.
	requestHeaderClientCA, ok := authConfigMap.Data["requestheader-client-ca-file"]
	if ok {
		app.requestHeaderClientCABytes = []byte(requestHeaderClientCA)
	}

	return nil
}

func getNamespace() string {
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}
	return metav1.NamespaceSystem
}

func (app *cdiAPIApp) getSelfSignedCert() error {
	var ok bool

	namespace := getNamespace()
	generateCerts := false
	secret, err := app.client.CoreV1().Secrets(namespace).Get(apiCertSecretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			generateCerts = true
		} else {
			return err
		}
	}

	if generateCerts {
		// Generate new certs if secret doesn't already exist
		caKeyPair, _ := triple.NewCA("kubecdi.io")
		keyPair, _ := triple.NewServerKeyPair(
			caKeyPair,
			"cdi-api."+namespace+".pod.cluster.local",
			"cdi-api",
			namespace,
			"cluster.local",
			nil,
			nil,
		)

		app.keyBytes = cert.EncodePrivateKeyPEM(keyPair.Key)
		app.certBytes = cert.EncodeCertPEM(keyPair.Cert)
		app.signingCertBytes = cert.EncodeCertPEM(caKeyPair.Cert)

		secret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      apiCertSecretName,
				Namespace: namespace,
				Labels: map[string]string{
					CDI_COMPONENT_LABEL: "cdi-api-aggregator",
				},
			},
			Type: "Opaque",
			Data: map[string][]byte{
				certBytesValue:        app.certBytes,
				keyBytesValue:         app.keyBytes,
				signingCertBytesValue: app.signingCertBytes,
			},
		}
		_, err := app.client.CoreV1().Secrets(namespace).Create(&secret)
		if err != nil {
			return err
		}
	} else {
		// retrieve self signed cert info from secret

		app.certBytes, ok = secret.Data[certBytesValue]
		if !ok {
			return errors.Errorf("%s value not found in %s cdi-api secret", certBytesValue, apiCertSecretName)
		}
		app.keyBytes, ok = secret.Data[keyBytesValue]
		if !ok {
			return errors.Errorf("%s value not found in %s cdi-api secret", keyBytesValue, apiCertSecretName)
		}
		app.signingCertBytes, ok = secret.Data[signingCertBytesValue]
		if !ok {
			return errors.Errorf("%s value not found in %s cdi-api secret", signingCertBytesValue, apiCertSecretName)
		}
	}
	return nil
}

func (app *cdiAPIApp) startTLS() error {

	errors := make(chan error)

	keyFile := filepath.Join(app.certsDirectory, "/key.pem")
	certFile := filepath.Join(app.certsDirectory, "/cert.pem")
	signingCertFile := filepath.Join(app.certsDirectory, "/signingCert.pem")
	clientCAFile := filepath.Join(app.certsDirectory, "/clientCA.crt")

	// Write the certs to disk
	err := ioutil.WriteFile(clientCAFile, app.clientCABytes, 0600)
	if err != nil {
		return err
	}

	if len(app.requestHeaderClientCABytes) != 0 {
		f, err := os.OpenFile(clientCAFile, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.Write(app.requestHeaderClientCABytes)
		if err != nil {
			return err
		}
	}

	err = ioutil.WriteFile(keyFile, app.keyBytes, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(certFile, app.certBytes, 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(signingCertFile, app.signingCertBytes, 0600)
	if err != nil {
		return err
	}

	// create the client CA pool.
	// This ensures we're talking to the k8s api server
	pool, err := cert.NewPool(clientCAFile)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		ClientCAs: pool,
		// A RequestClientCert request means we're not guaranteed
		// a client has been authenticated unless they provide a peer
		// cert.
		//
		// Make sure to verify in subresource endpoint that peer cert
		// was provided before processing request. If the peer cert is
		// given on the connection, then we can be guaranteed that it
		// was signed by the client CA in our pool.
		//
		// There is another ClientAuth type called 'RequireAndVerifyClientCert'
		// We can't use this type here because during the aggregated api status
		// check it attempts to hit '/' on our api endpoint to verify an http
		// response is given. That status request won't send a peer cert regardless
		// if the TLS handshake requests it. As a result, the TLS handshake fails
		// and our aggregated endpoint never becomes available.
		ClientAuth: tls.RequestClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	go func() {
		server := &http.Server{
			Addr:      fmt.Sprintf("%s:%d", app.bindAddress, app.bindPort),
			TLSConfig: tlsConfig,
		}

		errors <- server.ListenAndServeTLS(certFile, keyFile)
	}()

	// wait for server to exit
	return <-errors
}

func (app *cdiAPIApp) createWebhook() error {
	namespace := getNamespace()
	registerWebhook := false

	tokenPath := tokenMutationPath

	webhookRegistration, err := app.client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Get(apiMutationWebhook, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			registerWebhook = true
		} else {
			return err
		}
	}

	webHooks := []admissionregistrationv1beta1.Webhook{
		{
			Name: "uploadtoken-mutator.cdi.kubevirt.io",
			Rules: []admissionregistrationv1beta1.RuleWithOperations{{
				Operations: []admissionregistrationv1beta1.OperationType{admissionregistrationv1beta1.Create},
				Rule: admissionregistrationv1beta1.Rule{
					APIGroups:   []string{cdiv1.SchemeGroupVersion.Group},
					APIVersions: []string{cdiv1.SchemeGroupVersion.Version},
					Resources:   []string{"uploadtokens"},
				},
			}},
			ClientConfig: admissionregistrationv1beta1.WebhookClientConfig{
				Service: &admissionregistrationv1beta1.ServiceReference{
					Namespace: namespace,
					Name:      apiServiceName,
					Path:      &tokenPath,
				},
				CABundle: app.signingCertBytes,
			},
		},
	}

	if registerWebhook {
		_, err := app.client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Create(&admissionregistrationv1beta1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: apiMutationWebhook,
				Labels: map[string]string{
					CDI_COMPONENT_LABEL: apiMutationWebhook,
				},
			},
			Webhooks: webHooks,
		})
		if err != nil {
			return err
		}
	} else {
		for _, webhook := range webhookRegistration.Webhooks {
			if webhook.ClientConfig.Service != nil && webhook.ClientConfig.Service.Namespace != namespace {
				return fmt.Errorf("Webhook [%s] is already registered using services endpoints in a different namespace. Existing webhook registration must be deleted before virt-api can proceed.", apiMutationWebhook)
			}
		}

		// update registered webhook with our data
		webhookRegistration.Webhooks = webHooks

		_, err := app.client.AdmissionregistrationV1beta1().MutatingWebhookConfigurations().Update(webhookRegistration)
		if err != nil {
			return err
		}
	}

	http.HandleFunc(tokenPath, func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("hit hook")

		for key, val := range r.Header {

			fmt.Printf("%s=%s\n", key, val)
		}
	})

	return nil
}

func main() {
	defer glog.Flush()

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, configPath)
	if err != nil {
		glog.Fatalf("Unable to get kube config: %v\n", errors.WithStack(err))
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		glog.Fatalf("Unable to get kube client: %v\n", errors.WithStack(err))
	}

	app := &cdiAPIApp{
		bindAddress: defaultHost,
		bindPort:    defaultPort,
		client:      client,
	}
	app.certsDirectory, err = ioutil.TempDir("", "certsdir")
	if err != nil {
		glog.Fatalf("Unable to create certs temporary directory: %v\n", errors.WithStack(err))
	}

	err = app.getClientCert()
	if err != nil {
		glog.Fatalf("Unable to get client cert: %v\n", errors.WithStack(err))
	}

	err = app.getSelfSignedCert()
	if err != nil {
		glog.Fatalf("Unable to get self signed cert: %v\n", errors.WithStack(err))
	}

	err = app.createWebhook()
	if err != nil {
		glog.Fatalf("Unable to create webhook: %v\n", errors.WithStack(err))
	}

	err = app.startTLS()
	if err != nil {
		glog.Fatalf("TLS server failed: %v\n", errors.WithStack(err))
	}
}
