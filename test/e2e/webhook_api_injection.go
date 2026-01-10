package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	admissionreg "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	apiext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	admissionregclient "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiserviceclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	apiserviceclientv1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
)

const (
	serviceCAControllerNamespace = operatorclient.TargetNamespace
)

var _ = g.Describe("[sig-service-ca][Operator][Serial] Webhook and API CA bundle injection", func() {
	g.Context("apiservice-ca-bundle-injection", func() {
		g.It("[Operator][Serial] should inject CA bundle into APIService and restore after corruption", func() {
			testAPIServiceCABundleInjection(g.GinkgoTB())
		})
	})

	g.Context("crd-ca-bundle-injection", func() {
		g.It("[Operator][Serial] should inject CA bundle into CRD webhook and restore after corruption", func() {
			testCRDCABundleInjection(g.GinkgoTB())
		})
	})

	g.Context("mutatingwebhook-ca-bundle-injection", func() {
		g.It("[Operator][Serial] should inject CA bundle into MutatingWebhookConfiguration", func() {
			testMutatingWebhookCABundleInjection(g.GinkgoTB())
		})
	})

	g.Context("validatingwebhook-ca-bundle-injection", func() {
		g.It("[Operator][Serial] should inject CA bundle into ValidatingWebhookConfiguration", func() {
			testValidatingWebhookCABundleInjection(g.GinkgoTB())
		})
	})
})

// testAPIServiceCABundleInjection tests APIService CA bundle injection.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testAPIServiceCABundleInjection(t testing.TB) {
	adminConfig, err := getKubeConfig()
	if err != nil {
		t.Fatalf("error getting kube config: %v", err)
	}

	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	client := apiserviceclient.NewForConfigOrDie(adminConfig).ApiregistrationV1().APIServices()

	// Create an api service with the injection annotation
	randomGroup := fmt.Sprintf("e2e-%s", randSeq(10))
	version := "v1alpha1"
	obj := &apiregv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", version, randomGroup),
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                randomGroup,
			Version:              version,
			GroupPriorityMinimum: 1,
			VersionPriority:      1,
			// A service must be specified for validation to
			// accept a cabundle.
			Service: &apiregv1.ServiceReference{
				Namespace: "foo",
				Name:      "foo",
			},
		},
	}
	setInjectionAnnotation(&obj.ObjectMeta)
	createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating api service: %v", err)
	}
	defer func() {
		err := client.Delete(context.TODO(), obj.Name, metav1.DeleteOptions{})
		if err != nil {
			t.Errorf("Failed to cleanup api service: %v", err)
		}
	}()

	// Retrieve the expected CA bundle
	expectedCABundle, err := pollForSigningCABundle(t, adminClient)
	if err != nil {
		t.Fatalf("error retrieving the signing ca bundle: %v", err)
	}

	// Wait for the expected bundle to be injected
	injectedObj, err := pollForAPIService(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be injected: %v", err)
	}

	// Set an invalid ca bundle
	injectedObj.Spec.CABundle = append(injectedObj.Spec.CABundle, []byte("garbage")...)
	_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updated api service: %v", err)
	}

	// Check that the expected ca bundle is restored
	_, err = pollForAPIService(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
	}
}

// testCRDCABundleInjection tests CRD CA bundle injection for webhook conversion.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testCRDCABundleInjection(t testing.TB) {
	adminConfig, err := getKubeConfig()
	if err != nil {
		t.Fatalf("error getting kube config: %v", err)
	}

	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	client := apiextclient.NewForConfigOrDie(adminConfig).CustomResourceDefinitions()

	// Create a crd with the injection annotation
	randomGroup := fmt.Sprintf("e2e-%s.example.com", randSeq(10))
	pluralName := "cabundleinjectiontargets"
	version := "v1beta1"
	obj := &apiext.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s.%s", pluralName, randomGroup),
		},
		Spec: apiext.CustomResourceDefinitionSpec{
			Group: randomGroup,
			Scope: apiext.ClusterScoped,
			Names: apiext.CustomResourceDefinitionNames{
				Plural: pluralName,
				Kind:   "CABundleInjectionTarget",
			},
			Conversion: &apiext.CustomResourceConversion{
				// CA bundle will only be injected for a webhook converter
				Strategy: apiext.WebhookConverter,
				Webhook: &apiext.WebhookConversion{
					// CA bundle will be set on the following struct
					ClientConfig: &apiext.WebhookClientConfig{
						Service: &apiext.ServiceReference{
							Namespace: "foo",
							Name:      "foo",
						},
					},
					ConversionReviewVersions: []string{
						version,
					},
				},
			},
			// At least one version must be defined for a v1 crd to be valid
			Versions: []apiext.CustomResourceDefinitionVersion{
				{
					Name:    version,
					Storage: true,
					Schema: &apiext.CustomResourceValidation{
						OpenAPIV3Schema: &apiext.JSONSchemaProps{
							Type: "object",
						},
					},
				},
			},
		},
	}
	setInjectionAnnotation(&obj.ObjectMeta)
	createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating crd: %v", err)
	}
	defer func() {
		err := client.Delete(context.TODO(), obj.Name, metav1.DeleteOptions{})
		if err != nil {
			t.Errorf("Failed to cleanup crd: %v", err)
		}
	}()

	// Retrieve the expected CA bundle
	expectedCABundle, err := pollForSigningCABundle(t, adminClient)
	if err != nil {
		t.Fatalf("error retrieving the signing ca bundle: %v", err)
	}

	// Wait for the expected bundle to be injected
	injectedObj, err := pollForCRD(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be injected: %v", err)
	}

	// Set an invalid ca bundle
	whClientConfig := injectedObj.Spec.Conversion.Webhook.ClientConfig
	whClientConfig.CABundle = append(whClientConfig.CABundle, []byte("garbage")...)
	_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updated crd: %v", err)
	}

	// Check that the expected ca bundle is restored
	_, err = pollForCRD(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
	}
}

// testMutatingWebhookCABundleInjection tests MutatingWebhookConfiguration CA bundle injection.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testMutatingWebhookCABundleInjection(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	// Common webhook config
	webhookClientConfig := admissionreg.WebhookClientConfig{
		// A service must be specified for validation to
		// accept a cabundle.
		Service: &admissionreg.ServiceReference{
			Namespace: "foo",
			Name:      "foo",
		},
	}
	sideEffectNone := admissionreg.SideEffectClassNone

	client := adminClient.AdmissionregistrationV1().MutatingWebhookConfigurations()
	obj := &admissionreg.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "e2e-",
		},
		Webhooks: []admissionreg.MutatingWebhook{
			// Specify 2 webhooks to ensure more than 1 webhook will be updated
			{
				Name:                    "e2e-1.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
			{
				Name:                    "e2e-2.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
		},
	}
	// webhooks to add after initial creation to ensure
	// updates can be made for more than the original number of webhooks.
	webhooksToAdd := []admissionreg.MutatingWebhook{
		{
			Name:                    "e2e-3.example.com",
			ClientConfig:            webhookClientConfig,
			SideEffects:             &sideEffectNone,
			AdmissionReviewVersions: []string{"v1"},
		},
	}
	setInjectionAnnotation(&obj.ObjectMeta)
	createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating mutating webhook configuration: %v", err)
	}
	defer func() {
		err := client.Delete(context.TODO(), createdObj.Name, metav1.DeleteOptions{})
		if err != nil {
			t.Errorf("Failed to cleanup mutating webhook configuration: %v", err)
		}
	}()

	// Retrieve the expected CA bundle
	expectedCABundle, err := pollForSigningCABundle(t, adminClient)
	if err != nil {
		t.Fatalf("error retrieving the expected ca bundle: %v", err)
	}

	// Poll for the updated webhook configuration
	injectedObj, err := pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be injected: %v", err)
	}

	// Set an invalid ca bundle
	clientConfig := injectedObj.Webhooks[0].ClientConfig
	clientConfig.CABundle = append(clientConfig.CABundle, []byte("garbage")...)
	_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updated mutating webhook configuration: %v", err)
	}

	// Check that the ca bundle is restored
	injectedObj, err = pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
	}

	// Add an additional webhook and make sure CA bundle exists for all
	injectedObj.Webhooks = append(injectedObj.Webhooks, webhooksToAdd...)
	_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating mutating webhook configuration: %v", err)
	}

	// Check that the ca bundle for all webhooks (old and new)
	_, err = pollForMutatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
	}
}

// testValidatingWebhookCABundleInjection tests ValidatingWebhookConfiguration CA bundle injection.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testValidatingWebhookCABundleInjection(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	// Common webhook config
	webhookClientConfig := admissionreg.WebhookClientConfig{
		// A service must be specified for validation to
		// accept a cabundle.
		Service: &admissionreg.ServiceReference{
			Namespace: "foo",
			Name:      "foo",
		},
	}
	sideEffectNone := admissionreg.SideEffectClassNone

	client := adminClient.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	obj := &admissionreg.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "e2e-",
		},
		Webhooks: []admissionreg.ValidatingWebhook{
			// Specify 2 webhooks to ensure more than 1 webhook will be updated
			{
				Name:                    "e2e-1.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
			{
				Name:                    "e2e-2.example.com",
				ClientConfig:            webhookClientConfig,
				SideEffects:             &sideEffectNone,
				AdmissionReviewVersions: []string{"v1beta1"},
			},
		},
	}
	// webhooks to add after initial creation to ensure
	// updates can be made for more than the original number of webhooks.
	webhooksToAdd := []admissionreg.ValidatingWebhook{
		{
			Name:                    "e2e-3.example.com",
			ClientConfig:            webhookClientConfig,
			SideEffects:             &sideEffectNone,
			AdmissionReviewVersions: []string{"v1"},
		},
	}
	setInjectionAnnotation(&obj.ObjectMeta)
	createdObj, err := client.Create(context.TODO(), obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating validating webhook configuration: %v", err)
	}
	defer func() {
		err := client.Delete(context.TODO(), createdObj.Name, metav1.DeleteOptions{})
		if err != nil {
			t.Errorf("Failed to cleanup validating webhook configuration: %v", err)
		}
	}()

	// Retrieve the expected CA bundle
	expectedCABundle, err := pollForSigningCABundle(t, adminClient)
	if err != nil {
		t.Fatalf("error retrieving the expected ca bundle: %v", err)
	}

	// Poll for the updated webhook configuration
	injectedObj, err := pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be injected: %v", err)
	}

	// Set an invalid ca bundle
	clientConfig := injectedObj.Webhooks[0].ClientConfig
	clientConfig.CABundle = append(clientConfig.CABundle, []byte("garbage")...)
	_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updated validating webhook configuration: %v", err)
	}

	// Check that the ca bundle is restored
	injectedObj, err = pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
	}

	// Add an additional webhook and make sure CA bundle exists for all
	injectedObj.Webhooks = append(injectedObj.Webhooks, webhooksToAdd...)
	_, err = client.Update(context.TODO(), injectedObj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("error updating validating webhook configuration: %v", err)
	}

	// Check that the ca bundle for all webhooks (old and new)
	_, err = pollForValidatingWebhookConfiguration(t, client, createdObj.Name, expectedCABundle)
	if err != nil {
		t.Fatalf("error waiting for ca bundle to be re-injected: %v", err)
	}
}

// Helper functions copied from e2e_test.go

// pollForAPIService returns the specified APIService if its ca bundle
// matches the provided value before the polling timeout.
func pollForAPIService(t testing.TB, client apiserviceclientv1.APIServiceInterface, name string, expectedCABundle []byte) (*apiregv1.APIService, error) {
	resourceID := fmt.Sprintf("APIService %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		apiService, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		actualCABundle := apiService.Spec.CABundle
		if len(actualCABundle) == 0 {
			return nil, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return nil, fmt.Errorf("ca bundle does not match the expected value")
		}
		return apiService, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*apiregv1.APIService), nil
}

// pollForCRD returns the specified CustomResourceDefinition if the ca
// bundle for its conversion webhook config matches the provided value
// before the polling timeout.
func pollForCRD(t testing.TB, client apiextclient.CustomResourceDefinitionInterface, name string, expectedCABundle []byte) (*apiext.CustomResourceDefinition, error) {
	resourceID := fmt.Sprintf("CustomResourceDefinition %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		crd, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if crd.Spec.Conversion == nil || crd.Spec.Conversion.Webhook == nil || crd.Spec.Conversion.Webhook.ClientConfig == nil {
			return nil, fmt.Errorf("spec.conversion.webhook.webhook.clientConfig not set")
		}
		actualCABundle := crd.Spec.Conversion.Webhook.ClientConfig.CABundle
		if len(actualCABundle) == 0 {
			return nil, fmt.Errorf("ca bundle not injected")
		}
		if !bytes.Equal(actualCABundle, expectedCABundle) {
			return nil, fmt.Errorf("ca bundle does not match the expected value")
		}
		return crd, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*apiext.CustomResourceDefinition), nil
}

// pollForMutatingWebhookConfiguration returns the specified
// MutatingWebhookConfiguration if the ca bundle for all its webhooks match the
// provided value before the polling timeout.
func pollForMutatingWebhookConfiguration(t testing.TB, client admissionregclient.MutatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.MutatingWebhookConfiguration, error) {
	resourceID := fmt.Sprintf("MutatingWebhookConfiguration %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		webhookConfig, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		for _, webhook := range webhookConfig.Webhooks {
			err := checkWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return nil, err
			}
		}
		return webhookConfig, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*admissionreg.MutatingWebhookConfiguration), nil
}

// pollForValidatingWebhookConfiguration returns the specified
// ValidatingWebhookConfiguration if the ca bundle for all its webhooks match the
// provided value before the polling timeout.
func pollForValidatingWebhookConfiguration(t testing.TB, client admissionregclient.ValidatingWebhookConfigurationInterface, name string, expectedCABundle []byte) (*admissionreg.ValidatingWebhookConfiguration, error) {
	resourceID := fmt.Sprintf("ValidatingWebhookConfiguration %q", name)
	obj, err := pollForResource(t, resourceID, pollTimeout, func() (kruntime.Object, error) {
		webhookConfig, err := client.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		for _, webhook := range webhookConfig.Webhooks {
			err := checkWebhookCABundle(webhook.Name, expectedCABundle, webhook.ClientConfig.CABundle)
			if err != nil {
				return nil, err
			}
		}
		return webhookConfig, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*admissionreg.ValidatingWebhookConfiguration), nil
}

// checkWebhookCABundle checks that the ca bundle for the named webhook matches
// the expected value.
func checkWebhookCABundle(webhookName string, expectedCABundle, actualCABundle []byte) error {
	if len(actualCABundle) == 0 {
		return fmt.Errorf("ca bundle not injected for webhook %q", webhookName)
	}
	if !bytes.Equal(actualCABundle, expectedCABundle) {
		return fmt.Errorf("ca bundle does not match the expected value for webhook %q", webhookName)
	}
	return nil
}

// pollForSigningCABundle returns the bytes for the bundle key of the
// signing ca bundle configmap if the value is non-empty before the
// polling timeout.
func pollForSigningCABundle(t testing.TB, client *kubernetes.Clientset) ([]byte, error) {
	return pollForUpdatedConfigMap(t, client, serviceCAControllerNamespace, api.SigningCABundleConfigMapName, api.BundleDataKey, pollTimeout, nil)
}

// pollForUpdatedConfigMap returns the given configmap if its data changes from
// that provided before the polling timeout.
func pollForUpdatedConfigMap(t testing.TB, client *kubernetes.Clientset, namespace, name, key string, timeout time.Duration, oldValue []byte) ([]byte, error) {
	resourceID := fmt.Sprintf("ConfigMap \"%s/%s\"", namespace, name)
	obj, err := pollForResource(t, resourceID, timeout, func() (kruntime.Object, error) {
		configMap, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		// For rotation tests, we need to be more flexible about data size
		if len(configMap.Data) == 0 {
			return nil, fmt.Errorf("configmap has no data")
		}
		value, ok := configMap.Data[key]
		if !ok {
			return nil, fmt.Errorf("key %q is missing", key)
		}
		if oldValue != nil && value == string(oldValue) {
			return nil, fmt.Errorf("value for key %q has not changed", key)
		}
		return configMap, nil
	})
	if err != nil {
		return nil, err
	}
	configMap := obj.(*v1.ConfigMap)
	return []byte(configMap.Data[key]), nil
}

// getKubeConfig returns the kube config for the admin user.
func getKubeConfig() (*rest.Config, error) {
	confPath := "/tmp/admin.conf"
	if conf := os.Getenv("KUBECONFIG"); conf != "" {
		confPath = conf
	}

	client, err := clientcmd.LoadFromFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}
	adminConfig, err := clientcmd.NewDefaultClientConfig(*client, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading admin config: %w", err)
	}
	return adminConfig, nil
}
