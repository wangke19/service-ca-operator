package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/clock"

	operatorv1client "github.com/openshift/client-go/operator/clientset/versioned"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator"
	"github.com/openshift/service-ca-operator/test/util"
)

const (
	signingCertificateLifetime = 790 * 24 * time.Hour
)

var _ = g.Describe("[sig-service-ca][Operator][Serial] CA rotation", func() {
	g.Context("time-based-ca-rotation", func() {
		g.It("[Operator][Serial] should rotate CA when certificate is near expiry", func() {
			testTimeBasedCARotation(g.GinkgoTB())
		})
	})

	g.Context("forced-ca-rotation", func() {
		g.It("[Operator][Serial] should rotate CA when forced via operator config", func() {
			testForcedCARotation(g.GinkgoTB())
		})
	})
})

// testTimeBasedCARotation tests that when the CA is near expiry, it is rotated
// and all certificates and configmaps are refreshed.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testTimeBasedCARotation(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	adminConfig, err := getKubeConfig()
	if err != nil {
		t.Fatalf("error getting kube config: %v", err)
	}

	checkCARotation(t, adminClient, adminConfig, triggerTimeBasedRotation)
}

// testForcedCARotation tests that when CA rotation is forced via operator config,
// the CA is rotated and all certificates and configmaps are refreshed.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testForcedCARotation(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	adminConfig, err := getKubeConfig()
	if err != nil {
		t.Fatalf("error getting kube config: %v", err)
	}

	checkCARotation(t, adminClient, adminConfig, triggerForcedRotation)
}

// triggerRotationFunc is a function type that triggers CA rotation.
type triggerRotationFunc func(testing.TB, *kubernetes.Clientset, *rest.Config)

// checkCARotation is the main test logic for CA rotation tests.
// It creates test resources, triggers rotation, and validates that all
// certificates and configmaps are properly updated.
func checkCARotation(t testing.TB, client *kubernetes.Clientset, config *rest.Config, triggerRotation triggerRotationFunc) {
	ns, cleanup, err := createTestNamespace(t, client, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	// Prompt the creation of service cert secrets
	testServiceName := "test-service-" + randSeq(5)
	testSecretName := "test-secret-" + randSeq(5)
	testHeadlessServiceName := "test-headless-service-" + randSeq(5)
	testHeadlessSecretName := "test-headless-secret-" + randSeq(5)

	err = createServingCertAnnotatedService(client, testSecretName, testServiceName, ns.Name, false)
	if err != nil {
		t.Fatalf("error creating annotated service: %v", err)
	}
	if err = createServingCertAnnotatedService(client, testHeadlessSecretName, testHeadlessServiceName, ns.Name, true); err != nil {
		t.Fatalf("error creating annotated headless service: %v", err)
	}

	// Prompt the injection of the ca bundle into a configmap
	testConfigMapName := "test-configmap-" + randSeq(5)

	err = createAnnotatedCABundleInjectionConfigMap(client, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error creating annotated configmap: %v", err)
	}

	// Retrieve the pre-rotation service cert
	oldCertPEM, oldKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testSecretName, rotationPollTimeout, nil, nil)
	if err != nil {
		t.Fatalf("error retrieving service cert: %v", err)
	}
	oldHeadlessCertPEM, oldHeadlessKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testHeadlessSecretName, rotationPollTimeout, nil, nil)
	if err != nil {
		t.Fatalf("error retrieving headless service cert: %v", err)
	}

	// Retrieve the pre-rotation ca bundle
	oldBundlePEM, err := pollForInjectedCABundle(t, client, ns.Name, testConfigMapName, rotationPollTimeout, nil)
	if err != nil {
		t.Fatalf("error retrieving ca bundle: %v", err)
	}

	// Prompt CA rotation
	triggerRotation(t, client, config)

	// Retrieve the post-rotation service cert
	newCertPEM, newKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testSecretName, rotationTimeout, oldCertPEM, oldKeyPEM)
	if err != nil {
		t.Fatalf("error retrieving service cert: %v", err)
	}
	newHeadlessCertPEM, newHeadlessKeyPEM, err := pollForUpdatedServingCert(t, client, ns.Name, testHeadlessSecretName, rotationTimeout, oldHeadlessCertPEM, oldHeadlessKeyPEM)
	if err != nil {
		t.Fatalf("error retrieving headless service cert: %v", err)
	}

	// Retrieve the post-rotation ca bundle
	newBundlePEM, err := pollForInjectedCABundle(t, client, ns.Name, testConfigMapName, rotationTimeout, oldBundlePEM)
	if err != nil {
		t.Fatalf("error retrieving ca bundle: %v", err)
	}

	// Determine the dns name valid for the serving cert
	certs, err := util.PemToCerts(newCertPEM)
	if err != nil {
		t.Fatalf("error decoding pem to certs: %v", err)
	}
	dnsName := certs[0].Subject.CommonName

	checkRotation(t, dnsName, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM)

	for i := 0; i < 3; i++ { // 3 is an arbitrary number of hostnames to try
		dnsName := fmt.Sprintf("some-statefulset-%d.%s.%s.svc", i, testHeadlessServiceName, ns.Name)
		checkRotation(t, dnsName, oldHeadlessCertPEM, oldHeadlessKeyPEM, oldBundlePEM, newHeadlessCertPEM, newHeadlessKeyPEM, newBundlePEM)
	}
}

// checkRotation is a wrapper around util.CheckRotation that handles testing.TB interface.
// For standard Go tests, it delegates to util.CheckRotation.
// For Ginkgo tests, it directly performs the same validation without using t.Run.
func checkRotation(t testing.TB, dnsName string, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM []byte) {
	switch tt := t.(type) {
	case *testing.T:
		// Standard Go test - use util.CheckRotation which uses t.Run
		util.CheckRotation(tt, dnsName, oldCertPEM, oldKeyPEM, oldBundlePEM, newCertPEM, newKeyPEM, newBundlePEM)
	default:
		// Ginkgo test - inline the same logic without t.Run
		testCases := map[string]struct {
			certPEM   []byte
			keyPEM    []byte
			bundlePEM []byte
		}{
			"Pre-rotation": {
				certPEM:   oldCertPEM,
				keyPEM:    oldKeyPEM,
				bundlePEM: oldBundlePEM,
			},
			"Server rotated": {
				certPEM:   newCertPEM,
				keyPEM:    newKeyPEM,
				bundlePEM: oldBundlePEM,
			},
			"Client refreshed": {
				certPEM:   oldCertPEM,
				keyPEM:    oldKeyPEM,
				bundlePEM: newBundlePEM,
			},
			"Server rotated and client refreshed": {
				certPEM:   newCertPEM,
				keyPEM:    newKeyPEM,
				bundlePEM: newBundlePEM,
			},
		}

		// Note: We simply fail on first error rather than using t.Run subtests
		// This is acceptable for Ginkgo tests where we already have descriptive test names
		for testName, tc := range testCases {
			checkClientTrust(t, testName, dnsName, tc.certPEM, tc.keyPEM, tc.bundlePEM)
		}
	}
}

// checkClientTrust verifies that a server configured with the provided cert and key will be
// trusted by a client with the given bundle.
// This is a copy of test/util/rotate.go:checkClientTrust adapted for testing.TB.
func checkClientTrust(t testing.TB, testName, dnsName string, certPEM, keyPEM, bundlePEM []byte) {
	// Implementation copied from util package to work with testing.TB
	// The original uses *testing.T which is not compatible with Ginkgo's GinkgoTB()

	certFile, err := os.CreateTemp("", v1.TLSCertKey)
	if err != nil {
		t.Fatalf("%s: error creating tmpfile for cert: %v", testName, err)
	}
	defer os.Remove(certFile.Name())

	if _, err = certFile.Write(certPEM); err != nil {
		t.Fatalf("%s: error writing cert to disk: %v", testName, err)
	}
	certFile.Close()

	keyFile, err := os.CreateTemp("", v1.TLSPrivateKeyKey)
	if err != nil {
		t.Fatalf("%s: error creating tmpfile for key: %v", testName, err)
	}
	defer os.Remove(keyFile.Name())

	if _, err = keyFile.Write(keyPEM); err != nil {
		t.Fatalf("%s: error writing key to disk: %v", testName, err)
	}
	keyFile.Close()

	listenerAddress := "127.0.0.1:0"
	ln, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		t.Fatalf("%s: net.Listen: %v", testName, err)
	}
	defer ln.Close()

	serverAddress := ln.Addr().String()
	serverPort := serverAddress[strings.LastIndex(serverAddress, ":")+1:]

	srv := http.Server{}
	go func() {
		if err := srv.ServeTLS(ln, certFile.Name(), keyFile.Name()); err != nil && err != http.ErrServerClosed {
			// Don't use t.Errorf in goroutine as it's not safe
		}
	}()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(bundlePEM)
	dialer := &net.Dialer{
		Timeout: 60 * time.Second,
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				addr = "127.0.0.1" + addr[strings.LastIndex(addr, ":"):]
				return dialer.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: dnsName,
			},
		},
		Timeout: 60 * time.Second,
	}

	clientAddress := fmt.Sprintf("https://%s:%s", dnsName, serverPort)
	_, err = client.Get(clientAddress)
	if err != nil {
		t.Fatalf("%s: failed to connect: %v\ncertPEM: %s\nkeyPEM: %s\nbundlePEM: %s", testName, err,
			base64.StdEncoding.EncodeToString(certPEM),
			base64.StdEncoding.EncodeToString(keyPEM),
			base64.StdEncoding.EncodeToString(bundlePEM),
		)
	}
}

// triggerTimeBasedRotation replaces the current CA cert with one that
// is not valid for the minimum required duration and waits for the CA
// to be rotated.
func triggerTimeBasedRotation(t testing.TB, client *kubernetes.Clientset, config *rest.Config) {
	// A rotation-prompting CA cert needs to be a renewed instance
	// (i.e. share the same public and private keys) of the current
	// cert to ensure that trust will be maintained for unrefreshed
	// clients and servers.

	// Retrieve current CA
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	// Store the old PEMs for comparison
	oldCACertPEM := secret.Data[v1.TLSCertKey]
	oldCAKeyPEM := secret.Data[v1.TLSPrivateKeyKey]

	currentCACerts, err := util.PemToCerts(secret.Data[v1.TLSCertKey])
	if err != nil {
		t.Fatalf("error unmarshaling %q: %v", v1.TLSCertKey, err)
	}
	currentCAKey, err := util.PemToKey(secret.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		t.Fatalf("error unmarshalling %q: %v", v1.TLSPrivateKeyKey, err)
	}
	currentCAConfig := &crypto.TLSCertificateConfig{
		Certs: currentCACerts,
		Key:   currentCAKey,
	}

	// Trigger rotation by renewing the current ca with an expiry that
	// is sooner than the minimum required duration.
	renewedCAConfig, err := operator.RenewSelfSignedCertificate(currentCAConfig, 1*time.Hour, true)
	if err != nil {
		t.Fatalf("error renewing ca to half-expired form: %v", err)
	}
	renewedCACertPEM, renewedCAKeyPEM, err := renewedCAConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("error encoding renewed ca to pem: %v", err)
	}

	// Write the renewed CA
	secret = &v1.Secret{
		Type: v1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name:      signingKeySecretName,
			Namespace: serviceCAControllerNamespace,
		},
		Data: map[string][]byte{
			v1.TLSCertKey:       renewedCACertPEM,
			v1.TLSPrivateKeyKey: renewedCAKeyPEM,
		},
	}
	_, _, err = resourceapply.ApplySecret(context.Background(), client.CoreV1(), events.NewInMemoryRecorder("test", clock.RealClock{}), secret)
	if err != nil {
		t.Fatalf("error updating secret with test CA: %v", err)
	}

	_ = pollForCARotation(t, client, oldCACertPEM, oldCAKeyPEM)
}

// triggerForcedRotation forces the rotation of the current CA via the
// operator config.
func triggerForcedRotation(t testing.TB, client *kubernetes.Clientset, config *rest.Config) {
	// Retrieve the cert and key PEM of the current CA to be able to
	// detect when rotation has completed.
	secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	caCertPEM := secret.Data[v1.TLSCertKey]
	caKeyPEM := secret.Data[v1.TLSPrivateKeyKey]

	// Set a custom validity duration longer than the default to
	// validate that a custom expiry on rotation is possible.
	defaultDuration := signingCertificateLifetime
	customDuration := defaultDuration + 1*time.Hour

	// Trigger a forced rotation by updating the operator config
	// with a reason.
	forceUnsupportedServiceCAConfigRotation(t, config, secret, customDuration)

	signingSecret := pollForCARotation(t, client, caCertPEM, caKeyPEM)

	// Check that the expiry of the new CA is longer than the default
	rawCert := signingSecret.Data[v1.TLSCertKey]
	certs, err := cert.ParseCertsPEM(rawCert)
	if err != nil {
		t.Fatalf("Failed to parse signing secret cert: %v", err)
	}
	if !certs[0].NotAfter.After(time.Now().Add(defaultDuration)) {
		t.Fatalf("Custom validity duration was not used to generate the new CA")
	}
}

// forceUnsupportedServiceCAConfigRotation updates the operator config to force CA rotation.
func forceUnsupportedServiceCAConfigRotation(t testing.TB, config *rest.Config, currentSigningKeySecret *v1.Secret, validityDuration time.Duration) {
	operatorClient, err := operatorv1client.NewForConfig(config)
	if err != nil {
		t.Fatalf("error creating operator client: %v", err)
	}
	operatorConfig, err := operatorClient.OperatorV1().ServiceCAs().Get(context.TODO(), api.OperatorConfigInstanceName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving operator config: %v", err)
	}
	var forceRotationReason string
	for i := 0; ; i++ {
		forceRotationReason = fmt.Sprintf("service-ca-e2e-force-rotation-reason-%d", i)
		if currentSigningKeySecret.Annotations[api.ForcedRotationReasonAnnotationName] != forceRotationReason {
			break
		}
	}
	rawUnsupportedServiceCAConfig, err := operator.RawUnsupportedServiceCAConfig(forceRotationReason, validityDuration)
	if err != nil {
		t.Fatalf("failed to create raw unsupported config overrides: %v", err)
	}
	operatorConfig.Spec.UnsupportedConfigOverrides.Raw = rawUnsupportedServiceCAConfig
	_, err = operatorClient.OperatorV1().ServiceCAs().Update(context.TODO(), operatorConfig, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating operator config: %v", err)
	}
}

// pollForCARotation polls for the signing secret to be changed in
// response to CA rotation.
func pollForCARotation(t testing.TB, client *kubernetes.Clientset, caCertPEM, caKeyPEM []byte) *v1.Secret {
	resourceID := fmt.Sprintf("Secret \"%s/%s\"", serviceCAControllerNamespace, signingKeySecretName)
	obj, err := pollForResource(t, resourceID, rotationPollTimeout, func() (kruntime.Object, error) {
		secret, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		// Check if both cert and key are still the same as the old values
		if bytes.Equal(secret.Data[v1.TLSCertKey], caCertPEM) && bytes.Equal(secret.Data[v1.TLSPrivateKeyKey], caKeyPEM) {
			return nil, fmt.Errorf("cert and key have not changed yet")
		}
		return secret, nil
	})
	if err != nil {
		t.Fatalf("error waiting for CA rotation: %v", err)
	}
	return obj.(*v1.Secret)
}

// pollForInjectedCABundle returns the bytes for the injection key in
// the targeted configmap if the value of the key changes from that
// provided before the polling timeout.
func pollForInjectedCABundle(t testing.TB, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	return pollForUpdatedConfigMap(t, client, namespace, name, api.InjectionDataKey, timeout, oldValue)
}
