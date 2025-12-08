package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
)

const (
	serviceCAOperatorPodPrefix = operatorclient.OperatorName
	serviceCAPodPrefix         = api.ServiceCADeploymentName
)

func getPodLogs(t *testing.T, client *kubernetes.Clientset, name, namespace string) (string, error) {
	rc, err := client.CoreV1().Pods(namespace).GetLogs(name, &v1.PodLogOptions{}).Stream(context.TODO())
	if err != nil {
		return "", err
	}
	defer rc.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rc)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}


// newPrometheusClientForConfig returns a new prometheus client for
// the provided kubeconfig.

// checkMetricsCollection tests whether metrics are being successfully scraped from at
// least one target in a namespace.


func TestE2E(t *testing.T) {
	// use /tmp/admin.conf (placed by ci-operator) or KUBECONFIG env
	confPath := "/tmp/admin.conf"
	if conf := os.Getenv("KUBECONFIG"); conf != "" {
		confPath = conf
	}

	// load client
	client, err := clientcmd.LoadFromFile(confPath)
	if err != nil {
		t.Fatalf("error loading config: %v", err)
	}
	adminConfig, err := clientcmd.NewDefaultClientConfig(*client, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("error loading admin config: %v", err)
	}
	adminClient, err := kubernetes.NewForConfig(adminConfig)
	if err != nil {
		t.Fatalf("error getting admin client: %v", err)
	}

	// the service-serving-cert-operator and controllers should be running as a stock OpenShift component. our first test is to
	// verify that all of the components are running.
	checkComponents(t, adminClient)

	// test the main feature. annotate service -> created secret
	// This inline test will be removed once OTE migration is complete.
	// The test implementation is in serving_cert.go for dual compatibility.
	t.Run("serving-cert-annotation", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
				testServingCertAnnotation(t, headless)
			})
		}
	})

	// test modified data in serving-cert-secret will regenerated
	t.Run("serving-cert-secret-modify-bad-tlsCert", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
				testServingCertSecretModifyBadTLSCert(t, headless)
			})
		}
	})

	// test extra data in serving-cert-secret will be removed
	t.Run("serving-cert-secret-add-data", func(t *testing.T) {
		for _, headless := range []bool{false, true} {
			t.Run(fmt.Sprintf("headless=%v", headless), func(t *testing.T) {
				testServingCertSecretAddData(t, headless)
			})
		}
	})

	// make sure that deleting service-cert-secret regenerates a secret again,
	// and that the secret allows successful connections in practice.
	t.Run("serving-cert-secret-delete-data", func(t *testing.T) {
		testServingCertSecretDeleteData(t)
	})

	// make sure that deleting aservice-cert-secret regenerates a secret again,
	// and that the secret allows successful connections in practice.
	t.Run("headless-stateful-serving-cert-secret-delete-data", func(t *testing.T) {
		testHeadlessStatefulServingCertSecretDeleteData(t)
	})

	// test ca bundle injection configmap
	t.Run("ca-bundle-injection-configmap", func(t *testing.T) {
		testCABundleInjectionConfigMap(t)
	})

	// test updated data in ca bundle injection configmap will be stomped on
	t.Run("ca-bundle-injection-configmap-update", func(t *testing.T) {
		testCABundleInjectionConfigMapUpdate(t)
	})

	// test vulnerable-legacy ca bundle injection configmap
	t.Run("vulnerable-legacy-ca-bundle-injection-configmap", func(t *testing.T) {
		testVulnerableLegacyCABundleInjectionConfigMap(t)
	})

	t.Run("metrics", func(t *testing.T) {
		// Test that the operator's metrics endpoint is being read by prometheus
		t.Run("collection", func(t *testing.T) {
			testMetricsCollection(t)
		})

		// Test that service CA metrics are collected
		t.Run("service-ca-metrics", func(t *testing.T) {
			testServiceCAMetrics(t)
		})
	})

	t.Run("refresh-CA", func(t *testing.T) {
		testRefreshCA(t)
	})

	// CA rotation tests - migrated to ca_rotation.go for OTE compatibility
	t.Run("time-based-ca-rotation", func(t *testing.T) {
		testTimeBasedCARotation(t)
	})

	t.Run("forced-ca-rotation", func(t *testing.T) {
		testForcedCARotation(t)
	})

	t.Run("apiservice-ca-bundle-injection", func(t *testing.T) {
		testAPIServiceCABundleInjection(t)
	})

	t.Run("crd-ca-bundle-injection", func(t *testing.T) {
		testCRDCABundleInjection(t)
	})

	t.Run("mutatingwebhook-ca-bundle-injection", func(t *testing.T) {
		testMutatingWebhookCABundleInjection(t)
	})

	t.Run("validatingwebhook-ca-bundle-injection", func(t *testing.T) {
		testValidatingWebhookCABundleInjection(t)
	})
}

