package e2e

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	prometheusv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	routeclient "github.com/openshift/client-go/route/clientset/versioned"
	"github.com/openshift/library-go/test/library/metrics"
	"github.com/openshift/service-ca-operator/pkg/operator/operatorclient"
	"github.com/openshift/service-ca-operator/test/util"
)

const (
	serviceCAOperatorNamespace = operatorclient.OperatorNamespace
	signingKeySecretName       = "signing-key"
)

var _ = g.Describe("[sig-service-ca][Operator][Serial] Metrics", func() {
	g.Context("metrics", func() {
		g.It("[Operator][Serial] should collect metrics from operator endpoint", func() {
			testMetricsCollection(g.GinkgoTB())
		})

		g.It("[Operator][Serial] should expose service CA expiry time metrics", func() {
			testServiceCAMetrics(g.GinkgoTB())
		})
	})
})

// testMetricsCollection tests that the operator's metrics endpoint is being read by prometheus.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testMetricsCollection(t testing.TB) {
	adminConfig, err := getKubeConfig()
	if err != nil {
		t.Fatalf("error getting kube config: %v", err)
	}

	promClient, err := newPrometheusClientForConfig(adminConfig)
	if err != nil {
		t.Fatalf("error initializing prometheus client: %v", err)
	}

	checkMetricsCollection(t, promClient, "openshift-service-ca-operator")
}

// testServiceCAMetrics tests that service CA metrics are collected.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testServiceCAMetrics(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	adminConfig, err := getKubeConfig()
	if err != nil {
		t.Fatalf("error getting kube config: %v", err)
	}

	promClient, err := newPrometheusClientForConfig(adminConfig)
	if err != nil {
		t.Fatalf("error initializing prometheus client: %v", err)
	}

	checkServiceCAMetrics(t, adminClient, promClient)
}

// Helper functions copied from e2e_test.go

// newPrometheusClientForConfig returns a new prometheus client for
// the provided kubeconfig.
func newPrometheusClientForConfig(config *rest.Config) (prometheusv1.API, error) {
	routeClient, err := routeclient.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating route client: %v", err)
	}
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating kube client: %v", err)
	}
	return metrics.NewPrometheusClient(context.TODO(), kubeClient, routeClient)
}

// checkMetricsCollection tests whether metrics are being successfully scraped from at
// least one target in a namespace.
func checkMetricsCollection(t testing.TB, promClient prometheusv1.API, namespace string) {
	// Metrics are scraped every 30s. Wait as long as 2 intervals to avoid failing if
	// the target is temporarily unhealthy.
	timeout := 60 * time.Second

	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		query := fmt.Sprintf("up{namespace=\"%s\"}", namespace)
		resultVector, err := runPromQueryForVector(t, promClient, query, time.Now())
		if err != nil {
			tlogf(t, "failed to execute prometheus query: %v", err)
			return false, nil
		}
		metricsCollected := false
		for _, sample := range resultVector {
			metricsCollected = sample.Value == 1
			if metricsCollected {
				// Metrics are successfully being scraped for at least one target in the namespace
				break
			}
		}
		return metricsCollected, nil
	})
	if err != nil {
		t.Fatalf("Health check of metrics collection in namespace %s did not succeed within %v", serviceCAOperatorNamespace, timeout)
	}
}

func runPromQueryForVector(t testing.TB, promClient prometheusv1.API, query string, sampleTime time.Time) (model.Vector, error) {
	results, warnings, err := promClient.Query(context.Background(), query, sampleTime)
	if err != nil {
		return nil, err
	}
	if len(warnings) > 0 {
		tlogf(t, "prometheus query emitted warnings: %v", warnings)
	}

	result, ok := results.(model.Vector)
	if !ok {
		return nil, fmt.Errorf("expecting vector type result, found: %v ", reflect.TypeOf(results))
	}

	return result, nil
}

func getSampleForPromQuery(t testing.TB, promClient prometheusv1.API, query string, sampleTime time.Time) (*model.Sample, error) {
	res, err := runPromQueryForVector(t, promClient, query, sampleTime)
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("no matching metrics found for query %s", query)
	}
	return res[0], nil
}

func checkServiceCAMetrics(t testing.TB, client *kubernetes.Clientset, promClient prometheusv1.API) {
	timeout := 120 * time.Second

	secret, err := client.CoreV1().Secrets(operatorclient.TargetNamespace).Get(context.TODO(), signingKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("error retrieving signing key secret: %v", err)
	}
	currentCACerts, err := util.PemToCerts(secret.Data[v1.TLSCertKey])
	if err != nil {
		t.Fatalf("error unmarshaling %q: %v", v1.TLSCertKey, err)
	}
	if len(currentCACerts) == 0 {
		t.Fatalf("no signing keys found")
	}

	want := currentCACerts[0].NotAfter
	err = wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		rawExpiryTime, err := getSampleForPromQuery(t, promClient, `service_ca_expiry_time_seconds`, time.Now())
		if err != nil {
			tlogf(t, "failed to get sample value: %v", err)
			return false, nil
		}
		if rawExpiryTime.Value == 0 { // The operator is starting
			tlogf(t, "got zero value")
			return false, nil
		}

		if float64(want.Unix()) != float64(rawExpiryTime.Value) {
			t.Fatalf("service ca expiry time mismatch expected %v observed %v", float64(want.Unix()), float64(rawExpiryTime.Value))
		}

		return true, nil
	})
	if err != nil {
		t.Fatalf("service ca expiry timer metrics collection failed: %v", err)
	}
}
