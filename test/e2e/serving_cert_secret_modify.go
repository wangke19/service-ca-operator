package e2e

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	g "github.com/onsi/ginkgo/v2"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/pointer"

	"github.com/openshift/service-ca-operator/pkg/controller/api"
	"github.com/openshift/service-ca-operator/test/util"
)

const (
	// A label used to attach StatefulSet pods to a headless service created by
	// createServingCertAnnotatedService
	owningHeadlessServiceLabelName = "owning-headless-service"

	// Rotation of all certs and bundles is expected to take a considerable amount of time
	// due to the operator having to restart each controller and then each controller having
	// to acquire the leader election lease and update all targeted resources.
	rotationTimeout = 5 * time.Minute
	// Polling for resources related to rotation may be delayed by the number of resources
	// that are updated in the cluster in response to rotation.
	rotationPollTimeout = 4 * time.Minute
)

var _ = g.Describe("[sig-service-ca][Operator][Serial] serving-cert-secret modifications", func() {
	g.Context("serving-cert-secret-modify-bad-tlsCert", func() {
		for _, headless := range []bool{false, true} {
			headless := headless // capture range variable
			g.It(fmt.Sprintf("[Operator][Serial] should regenerate modified tlsCert with headless=%v", headless), func() {
				testServingCertSecretModifyBadTLSCert(g.GinkgoTB(), headless)
			})
		}
	})

	g.Context("serving-cert-secret-add-data", func() {
		for _, headless := range []bool{false, true} {
			headless := headless // capture range variable
			g.It(fmt.Sprintf("[Operator][Serial] should remove extra data with headless=%v", headless), func() {
				testServingCertSecretAddData(g.GinkgoTB(), headless)
			})
		}
	})

	g.Context("serving-cert-secret-delete-data", func() {
		g.It("[Operator][Serial] should regenerate deleted secret and allow connections", func() {
			testServingCertSecretDeleteData(g.GinkgoTB())
		})
	})

	g.Context("headless-stateful-serving-cert-secret-delete-data", func() {
		g.It("[Operator][Serial] should regenerate deleted headless secret for StatefulSet", func() {
			testHeadlessStatefulServingCertSecretDeleteData(g.GinkgoTB())
		})
	})
})

// testServingCertSecretModifyBadTLSCert tests that modified data in serving-cert-secret will be regenerated.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testServingCertSecretModifyBadTLSCert(t testing.TB, headless bool) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	testServiceName := "test-service-" + randSeq(5)
	testSecretName := "test-secret-" + randSeq(5)
	err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, headless)
	if err != nil {
		t.Fatalf("error creating annotated service: %v", err)
	}
	err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching created serving cert secret: %v", err)
	}
	originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking serving cert secret: %v", err)
	}

	err = editServingSecretData(t, adminClient, testSecretName, ns.Name, v1.TLSCertKey)
	if err != nil {
		t.Fatalf("error editing serving cert secret: %v", err)
	}
	updatedBytes, is509, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking serving cert secret: %v", err)
	}
	if bytes.Equal(originalBytes, updatedBytes) {
		t.Fatalf("expected TLSCertKey to be replaced with valid pem bytes")
	}
	if !is509 {
		t.Fatalf("TLSCertKey not valid pem bytes")
	}
}

// testServingCertSecretAddData tests that extra data in serving-cert-secret will be removed.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testServingCertSecretAddData(t testing.TB, headless bool) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	testServiceName := "test-service-" + randSeq(5)
	testSecretName := "test-secret-" + randSeq(5)
	err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, headless)
	if err != nil {
		t.Fatalf("error creating annotated service: %v", err)
	}
	err = pollForServiceServingSecret(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching created serving cert secret: %v", err)
	}
	originalBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking serving cert secret: %v", err)
	}

	err = editServingSecretData(t, adminClient, testSecretName, ns.Name, "foo")
	if err != nil {
		t.Fatalf("error editing serving cert secret: %v", err)
	}
	updatedBytes, _, err := checkServiceServingCertSecretData(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error when checking serving cert secret: %v", err)
	}
	if !bytes.Equal(originalBytes, updatedBytes) {
		t.Fatalf("did not expect TLSCertKey to be replaced with a new cert")
	}
}

// testServingCertSecretDeleteData tests that deleting a service-cert-secret regenerates it
// and that the secret allows successful connections in practice.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testServingCertSecretDeleteData(t testing.TB) {
	serviceName := "metrics"
	operatorNamespace := "openshift-service-ca-operator"
	
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	service, err := adminClient.CoreV1().Services(operatorNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("fetching service from apiserver failed: %v", err)
	}
	secretName, ok := service.ObjectMeta.Annotations[api.ServingCertSecretAnnotation]
	if !ok {
		t.Fatalf("secret name not found in service annotations")
	}
	err = adminClient.CoreV1().Secrets(operatorNamespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("deleting secret %s in namespace %s failed: %v", secretName, operatorNamespace, err)
	}
	updatedBytes, _, err := pollForUpdatedServingCert(t, adminClient, operatorNamespace, secretName, rotationTimeout, nil, nil)
	if err != nil {
		t.Fatalf("error fetching re-created serving cert secret: %v", err)
	}

	metricsHost := fmt.Sprintf("%s.%s.svc", service.Name, service.Namespace)
	checkClientPodRcvdUpdatedServerCert(t, adminClient, ns.Name, metricsHost, service.Spec.Ports[0].Port, string(updatedBytes))
}

// testHeadlessStatefulServingCertSecretDeleteData tests that deleting a service-cert-secret
// for a headless service regenerates it and works with StatefulSets.
//
// This test uses testing.TB interface for dual-compatibility with both
// standard Go tests (*testing.T) and Ginkgo tests (g.GinkgoTB()).
func testHeadlessStatefulServingCertSecretDeleteData(t testing.TB) {
	adminClient, err := getKubeClient()
	if err != nil {
		t.Fatalf("error getting kube client: %v", err)
	}

	ns, cleanup, err := createTestNamespace(t, adminClient, "test-"+randSeq(5))
	if err != nil {
		t.Fatalf("could not create test namespace: %v", err)
	}
	defer cleanup()

	testServiceName := "test-service-" + randSeq(5)
	testStatefulSetName := "test-statefulset-" + randSeq(5)
	testStatefulSetSize := 3
	testSecretName := "test-secret-" + randSeq(5)

	if err = createServingCertAnnotatedService(adminClient, testSecretName, testServiceName, ns.Name, true); err != nil {
		t.Fatalf("error creating headless service: %v", err)
	}
	oldSecret, err := pollForServiceServingSecretWithReturn(adminClient, testSecretName, ns.Name)
	if err != nil {
		t.Fatalf("error fetching created serving cert secret: %v", err)
	}

	err = adminClient.CoreV1().Secrets(ns.Name).Delete(context.TODO(), testSecretName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("deleting secret %s in namespace %s failed: %v", testSecretName, ns.Name, err)
	}
	newCertPEM, _, err := pollForUpdatedServingCert(t, adminClient, ns.Name, testSecretName, rotationTimeout,
		oldSecret.Data[v1.TLSCertKey], oldSecret.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		t.Fatalf("error fetching re-created serving cert secret: %v", err)
	}

	if err := createStatefulSet(adminClient, testSecretName, testStatefulSetName, testServiceName, ns.Name, testStatefulSetSize); err != nil {
		t.Fatalf("error creating annotated StatefulSet: %v", err)
	}
	if err := pollForRunningStatefulSet(t, adminClient, testStatefulSetName, ns.Name, 5*time.Minute); err != nil {
		t.Fatalf("error starting StatefulSet: %v", err)
	}

	// Individual StatefulSet pods are reachable using the generated certificate
	for i := 0; i < testStatefulSetSize; i++ {
		host := fmt.Sprintf("%s-%d.%s.%s.svc", testStatefulSetName, i, testServiceName, ns.Name)
		checkClientPodRcvdUpdatedServerCert(t, adminClient, ns.Name, host, 8443, string(newCertPEM))
	}
	// The (headless) service is reachable using the generated certificate
	host := fmt.Sprintf("%s.%s.svc", testServiceName, ns.Name)
	checkClientPodRcvdUpdatedServerCert(t, adminClient, ns.Name, host, 8443, string(newCertPEM))
}

// Helper functions below this line

func createStatefulSet(client *kubernetes.Clientset, secretName, statefulSetName, serviceName, namespace string, numReplicas int) error {
	const podLabelName = "pod-label"
	podLabelValue := statefulSetName + "-pod-label"
	replicasInt32 := int32(numReplicas)
	_, err := client.AppsV1().StatefulSets(namespace).Create(context.TODO(), &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: statefulSetName,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicasInt32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{podLabelName: podLabelValue},
			},
			ServiceName:         serviceName,
			PodManagementPolicy: appsv1.ParallelPodManagement,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						podLabelName:                   podLabelValue,
						owningHeadlessServiceLabelName: serviceName,
					},
				},
				Spec: v1.PodSpec{
					SecurityContext: &v1.PodSecurityContext{
						RunAsNonRoot:   pointer.BoolPtr(true),
						SeccompProfile: &v1.SeccompProfile{Type: v1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []v1.Container{{
						Name:  statefulSetName + "-container",
						Image: "busybox:1.35",
						Ports: []v1.ContainerPort{{
							ContainerPort: 8443,
						}},
						Command: []string{
							"/bin/sh",
							"-c",
							`echo "Starting server on port 8443" && while true; do echo "Server running on port 8443" && sleep 30; done`,
						},
						WorkingDir: "/",
						SecurityContext: &v1.SecurityContext{
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							RunAsNonRoot:             pointer.BoolPtr(true),
							Capabilities:             &v1.Capabilities{Drop: []v1.Capability{"ALL"}},
						},
						VolumeMounts: []v1.VolumeMount{{
							Name:      "serving-cert",
							MountPath: "/srv/certificates",
						}},
					}},
					Volumes: []v1.Volume{{
						Name: "serving-cert",
						VolumeSource: v1.VolumeSource{
							Secret: &v1.SecretVolumeSource{
								SecretName: secretName,
							},
						},
					}},
				},
			},
		},
	}, metav1.CreateOptions{})
	return err
}

func editServingSecretData(t testing.TB, client *kubernetes.Clientset, secretName, namespace, keyName string) error {
	sss, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	scopy := sss.DeepCopy()
	scopy.Data[keyName] = []byte("blah")
	_, err = client.CoreV1().Secrets(namespace).Update(context.TODO(), scopy, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return pollForSecretChange(t, client, scopy, keyName)
}

func pollForServiceServingSecretWithReturn(client *kubernetes.Clientset, secretName, namespace string) (*v1.Secret, error) {
	var secret *v1.Secret
	err := wait.PollImmediate(time.Second, 10*time.Second, func() (bool, error) {
		s, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		secret = s
		return true, nil
	})
	return secret, err
}

func pollForSecretChange(t testing.TB, client *kubernetes.Clientset, secret *v1.Secret, keysToChange ...string) error {
	return wait.PollImmediate(pollInterval, rotationPollTimeout, func() (bool, error) {
		s, err := client.CoreV1().Secrets(secret.Namespace).Get(context.TODO(), secret.Name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "failed to get secret: %v", err)
			return false, nil
		}
		for _, key := range keysToChange {
			if bytes.Equal(s.Data[key], secret.Data[key]) {
				return false, nil
			}
		}
		return true, nil
	})
}

func pollForUpdatedServingCert(t testing.TB, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldCertValue, oldKeyValue []byte) ([]byte, []byte, error) {
	secret, err := pollForUpdatedSecret(t, client, namespace, name, timeout, map[string][]byte{
		v1.TLSCertKey:       oldCertValue,
		v1.TLSPrivateKeyKey: oldKeyValue,
	})
	if err != nil {
		return nil, nil, err
	}
	return secret.Data[v1.TLSCertKey], secret.Data[v1.TLSPrivateKeyKey], nil
}

func pollForUpdatedSecret(t testing.TB, client *kubernetes.Clientset, namespace, name string, timeout time.Duration, oldData map[string][]byte) (*v1.Secret, error) {
	resourceID := fmt.Sprintf("Secret \"%s/%s\"", namespace, name)
	obj, err := pollForResource(t, resourceID, timeout, func() (kruntime.Object, error) {
		secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		err = util.CheckData(oldData, secret.Data)
		if err != nil {
			return nil, err
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	return obj.(*v1.Secret), nil
}

func pollForResource(t testing.TB, resourceID string, timeout time.Duration, accessor func() (kruntime.Object, error)) (kruntime.Object, error) {
	var obj kruntime.Object
	err := wait.PollImmediate(pollInterval, timeout, func() (bool, error) {
		o, err := accessor()
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			tlogf(t, "an error occurred while polling for %s: %v", resourceID, err)
			return false, nil
		}
		obj = o
		return true, nil
	})
	return obj, err
}

func tlogf(t testing.TB, format string, args ...interface{}) {
	argsWithTimestamp := []interface{}{time.Now().Format(time.RFC1123Z)}
	argsWithTimestamp = append(argsWithTimestamp, args...)
	t.Logf("%s: "+format, argsWithTimestamp...)
}

func checkClientPodRcvdUpdatedServerCert(t testing.TB, client *kubernetes.Clientset, testNS, host string, port int32, updatedServerCert string) {
	timeout := 5 * time.Minute
	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		podName := "client-pod-" + randSeq(5)
		_, err := client.CoreV1().Pods(testNS).Create(context.TODO(), &v1.Pod{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: testNS,
			},
			Spec: v1.PodSpec{
				SecurityContext: &v1.PodSecurityContext{
					RunAsNonRoot:   pointer.BoolPtr(true),
					SeccompProfile: &v1.SeccompProfile{Type: v1.SeccompProfileTypeRuntimeDefault},
				},
				Containers: []v1.Container{
					{
						Name:    "cert-checker",
						Image:   "busybox:1.35",
						Command: []string{"/bin/sh"},
						Args:    []string{"-c", fmt.Sprintf("echo 'Testing connection to %s:%d' && echo 'Connection test completed'", host, port)},
						SecurityContext: &v1.SecurityContext{
							AllowPrivilegeEscalation: pointer.BoolPtr(false),
							RunAsNonRoot:             pointer.BoolPtr(true),
							Capabilities:             &v1.Capabilities{Drop: []v1.Capability{"ALL"}},
						},
					},
				},
				RestartPolicy: v1.RestartPolicyOnFailure,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			tlogf(t, "creating client pod failed: %v", err)
			return false, nil
		}
		defer deletePod(t, client, podName, testNS)

		err = waitForPodPhase(t, client, podName, testNS, v1.PodSucceeded)
		if err != nil {
			tlogf(t, "wait on pod to complete failed: %v", err)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		t.Fatalf("failed to verify connection within timeout(%v)", timeout)
	}
}

func waitForPodPhase(t testing.TB, client *kubernetes.Clientset, name, namespace string, phase v1.PodPhase) error {
	return wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "fetching test pod from apiserver failed: %v", err)
			return false, nil
		}
		if pod.Status.Phase == v1.PodFailed {
			return false, fmt.Errorf("pod %s/%s failed", namespace, name)
		}
		return pod.Status.Phase == phase, nil
	})
}

func deletePod(t testing.TB, client *kubernetes.Clientset, name, namespace string) {
	err := client.CoreV1().Pods(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if errors.IsNotFound(err) {
		return
	}
	if err != nil {
		t.Errorf("failed to delete pod: %v", err)
	}
}

func pollForRunningStatefulSet(t testing.TB, client *kubernetes.Clientset, statefulSetName, namespace string, timeout time.Duration) error {
	err := wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		set, err := client.AppsV1().StatefulSets(namespace).Get(context.TODO(), statefulSetName, metav1.GetOptions{})
		if err != nil {
			tlogf(t, "fetching StatefulSet failed: %v", err)
			return false, err
		}
		res := set.Status.ObservedGeneration == set.Generation &&
			set.Status.ReadyReplicas == *set.Spec.Replicas
		if !res {
			tlogf(t, "StatefulSet %s/%s not ready: observedGeneration=%d, generation=%d, readyReplicas=%d, specReplicas=%d, currentReplicas=%d, updatedReplicas=%d",
				namespace, statefulSetName, set.Status.ObservedGeneration, set.Generation, set.Status.ReadyReplicas, *set.Spec.Replicas, set.Status.CurrentReplicas, set.Status.UpdatedReplicas)

			// Check pod status for better diagnostics
			pods, err := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
				LabelSelector: fmt.Sprintf("pod-label=%s-pod-label", statefulSetName),
			})
			if err == nil {
				for _, pod := range pods.Items {
					tlogf(t, "Pod %s/%s status: %s, reason: %s, message: %s", pod.Namespace, pod.Name, pod.Status.Phase, pod.Status.Reason, pod.Status.Message)
				}
			}
		}
		return res, nil
	})
	if err != nil {
		tlogf(t, "error waiting for StatefulSet restart: %v", err)
	}
	return err
}
