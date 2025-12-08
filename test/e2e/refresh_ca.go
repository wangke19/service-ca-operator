package e2e

import (
	"context"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
)

var _ = g.Describe("[sig-service-ca][Operator][Serial] CA refresh", func() {
	g.Context("refresh-CA", func() {
		g.It("[Operator][Serial] should refresh certificates and configmaps when CA is deleted and recreated", func() {
			testRefreshCA(g.GinkgoTB())
		})
	})
})

// testRefreshCA tests that when the CA is deleted, it is recreated and all
// certificates and configmaps are refreshed.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testRefreshCA(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	// create secrets
	testServiceName := "test-service-" + randSeq(5)
	testSecretName := "test-secret-" + randSeq(5)
	testHeadlessServiceName := "test-headless-service-" + randSeq(5)
	testHeadlessSecretName := "test-headless-secret-" + randSeq(5)

	err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, false)
	if err != nil {
		t.Fatalf("error creating annotated service: %v", err)
	}
	if err = createServingCertAnnotatedService(adminClient, testHeadlessSecretName, testHeadlessServiceName, ns.Name, true); err != nil {
		t.Fatalf("error creating annotated headless service: %v", err)
	}

	secret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching created serving cert secret: %v", err)
	}
	secretCopy := secret.DeepCopy()
	headlessSecret, err := pollForServiceServingSecretWithReturn(adminClient, testHeadlessSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching created serving cert secret: %v", err)
	}
	headlessSecretCopy := headlessSecret.DeepCopy()

	// create configmap
	testConfigMapName := "test-configmap-" + randSeq(5)

	err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error creating annotated configmap: %v", err)
	}

	configmap, err := pollForCABundleInjectionConfigMapWithReturn(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching ca bundle injection configmap: %v", err)
	}
	configmapCopy := configmap.DeepCopy()
	err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking ca bundle injection configmap: %v", err)
	}

	// delete ca secret
	err = adminClient.CoreV1().Secrets(serviceCAControllerNamespace).Delete(context.TODO(), signingKeySecretName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("error deleting signing key: %v", err)
	}

	// make sure it's recreated
	err = pollForCARecreation(adminClient)
	if err != nil {
		t.Fatalf("signing key was not recreated: %v", err)
	}

	err = pollForConfigMapChange(t, adminClient, configmapCopy, api.InjectionDataKey)
	if err != nil {
		t.Fatalf("configmap bundle did not change: %v", err)
	}

	err = pollForSecretChange(t, adminClient, secretCopy, v1.TLSCertKey, v1.TLSPrivateKeyKey)
	if err != nil {
		t.Fatalf("secret cert did not change: %v", err)
	}
	if err := pollForSecretChange(t, adminClient, headlessSecretCopy); err != nil {
		t.Fatalf("headless secret cert did not change: %v", err)
	}
}

// Helper functions copied from e2e_test.go

// pollForCARecreation polls for the signing secret to be re-created in
// response to CA secret deletion.
func pollForCARecreation(client *kubernetes.Clientset) error {
	return wait.PollImmediate(time.Second, rotationPollTimeout, func() (bool, error) {
		_, err := client.CoreV1().Secrets(serviceCAControllerNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}
