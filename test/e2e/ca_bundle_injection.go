package e2e

import (
	"context"
	"fmt"
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

var _ = g.Describe("[sig-service-ca][Operator][Serial] CA bundle injection", func() {
	g.Context("ca-bundle-injection-configmap", func() {
		g.It("[Operator][Serial] should inject CA bundle into annotated configmap", func() {
			testCABundleInjectionConfigMap(g.GinkgoTB())
		})
	})

	g.Context("ca-bundle-injection-configmap-update", func() {
		g.It("[Operator][Serial] should restore modified CA bundle injection data", func() {
			testCABundleInjectionConfigMapUpdate(g.GinkgoTB())
		})
	})

	g.Context("vulnerable-legacy-ca-bundle-injection-configmap", func() {
		g.It("[Operator][Serial] should handle vulnerable legacy CA bundle injection correctly", func() {
			testVulnerableLegacyCABundleInjectionConfigMap(g.GinkgoTB())
		})
	})
})

// testCABundleInjectionConfigMap tests ca bundle injection configmap.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testCABundleInjectionConfigMap(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	testConfigMapName := "test-configmap-" + randSeq(5)

	err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error creating annotated configmap: %v", err)
	}

	err = pollForCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching ca bundle injection configmap: %v", err)
	}

	err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking ca bundle injection configmap: %v", err)
	}
}

// testCABundleInjectionConfigMapUpdate tests updated data in ca bundle injection configmap will be stomped on.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testCABundleInjectionConfigMapUpdate(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	testConfigMapName := "test-configmap-" + randSeq(5)

	err = createAnnotatedCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error creating annotated configmap: %v", err)
	}

	err = pollForCABundleInjectionConfigMap(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching ca bundle injection configmap: %v", err)
	}

	err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking ca bundle injection configmap: %v", err)
	}

	err = editConfigMapCABundleInjectionData(t, adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error editing ca bundle injection configmap: %v", err)
	}

	err = checkConfigMapCABundleInjectionData(adminClient, testConfigMapName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking ca bundle injection configmap: %v", err)
	}
}

// testVulnerableLegacyCABundleInjectionConfigMap tests vulnerable-legacy ca bundle injection configmap.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testVulnerableLegacyCABundleInjectionConfigMap(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	// names other than the one we need are never published to
	neverPublished := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-configmap-" + randSeq(5),
			Annotations: map[string]string{api.VulnerableLegacyInjectCABundleAnnotationName: "true"},
		},
	}
	_, err = adminClient.CoreV1().ConfigMaps(ns.Name).Create(context.TODO(), neverPublished, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// with this name, content should never be published.  We wait ten seconds
	err = pollForConfigMapCAInjection(adminClient, neverPublished.Name, ns.Name)
	if err != wait.ErrWaitTimeout {
		t.Fatal(err)
	}

	publishedConfigMap := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "openshift-service-ca.crt",
			Annotations: map[string]string{api.VulnerableLegacyInjectCABundleAnnotationName: "true"},
		},
	}
	publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Create(context.TODO(), publishedConfigMap, metav1.CreateOptions{})
	// tolerate "already exists" to handle the case where we're running the e2e on a cluster that already has this
	// configmap present and injected.
	if err != nil && !errors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Get(context.TODO(), "openshift-service-ca.crt", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// this one should be injected
	err = pollForConfigMapCAInjection(adminClient, publishedConfigMap.Name, ns.Name)
	if err != nil {
		t.Fatal(err)
	}
	originalContent := publishedConfigMap.Data[api.InjectionDataKey]

	_, hasNewStyleAnnotation := publishedConfigMap.Annotations[api.InjectCABundleAnnotationName]
	if hasNewStyleAnnotation {
		// add old injection to be sure only new is honored
		publishedConfigMap.Annotations[api.VulnerableLegacyInjectCABundleAnnotationName] = "true"
		publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Update(context.TODO(), publishedConfigMap, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		// hand-off to new injector
		publishedConfigMap.Annotations[api.InjectCABundleAnnotationName] = "true"
		publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Update(context.TODO(), publishedConfigMap, metav1.UpdateOptions{})
		if err != nil {
			t.Fatal(err)
		}
	}

	// the content should now change pretty quick.  We sleep because it's easier than writing a new poll and I'm pressed for time
	time.Sleep(5 * time.Second)
	publishedConfigMap, err = adminClient.CoreV1().ConfigMaps(ns.Name).Get(context.TODO(), publishedConfigMap.Name, metav1.GetOptions{})

	// if we changed the injection, we should see different content
	if hasNewStyleAnnotation {
		if publishedConfigMap.Data[api.InjectionDataKey] != originalContent {
			t.Fatal("Content switch and it should not have.  The better ca bundle should win.")
		}
	} else {
		if publishedConfigMap.Data[api.InjectionDataKey] == originalContent {
			t.Fatal("Content did not update like it was supposed to.  The better ca bundle should win.")
		}
	}
}

// Helper functions copied from e2e_test.go

func createAnnotatedCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	obj := &v1.ConfigMap{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
		},
	}
	setInjectionAnnotation(&obj.ObjectMeta)
	_, err := client.CoreV1().ConfigMaps(namespace).Create(context.TODO(), obj, metav1.CreateOptions{})
	return err
}

func pollForCABundleInjectionConfigMap(client *kubernetes.Clientset, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		_, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func pollForCABundleInjectionConfigMapWithReturn(client *kubernetes.Clientset, configMapName, namespace string) (*v1.ConfigMap, error) {
	var configmap *v1.ConfigMap
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		configmap = cm
		return true, nil
	})
	return configmap, err
}

func checkConfigMapCABundleInjectionData(client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if len(cm.Data) != 1 {
		return err
	}
	_, ok := cm.Data[api.InjectionDataKey]
	if !ok {
		return err
	}
	return nil
}

func pollForConfigMapCAInjection(client *kubernetes.Clientset, configMapName, namespace string) error {
	return wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		if len(cm.Data) != 1 {
			return false, nil
		}
		_, ok := cm.Data[api.InjectionDataKey]
		if !ok {
			return false, nil
		}
		return true, nil
	})
}

func editConfigMapCABundleInjectionData(t testing.TB, client *kubernetes.Clientset, configMapName, namespace string) error {
	cm, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	cmcopy := cm.DeepCopy()
	if len(cmcopy.Data) != 1 {
		return fmt.Errorf("ca bundle injection configmap missing data")
	}
	cmcopy.Data["foo"] = "blah"
	_, err = client.CoreV1().ConfigMaps(namespace).Update(context.TODO(), cmcopy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return pollForConfigMapChange(t, client, cmcopy, "foo")
}

func pollForConfigMapChange(t testing.TB, client *kubernetes.Clientset, compareConfigMap *v1.ConfigMap, keysToChange ...string) error {
	return wait.PollImmediate(pollInterval, rotationPollTimeout, func() (bool, error) {
		cm, err := client.CoreV1().ConfigMaps(compareConfigMap.Namespace).Get(context.TODO(), compareConfigMap.Name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "failed to get configmap: %v", err)
			return false, nil
		}
		for _, key := range keysToChange {
			if cm.Data[key] == compareConfigMap.Data[key] {
				return false, nil
			}
		}
		return true, nil
	})
}

func setInjectionAnnotation(objMeta *metav1.ObjectMeta) {
	if objMeta.Annotations == nil {
		objMeta.Annotations = map[string]string{}
	}
	objMeta.Annotations[api.InjectCABundleAnnotationName] = "true"
}
