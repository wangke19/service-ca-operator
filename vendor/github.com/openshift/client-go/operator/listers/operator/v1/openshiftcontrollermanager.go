// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	operatorv1 "github.com/openshift/api/operator/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// OpenShiftControllerManagerLister helps list OpenShiftControllerManagers.
// All objects returned here must be treated as read-only.
type OpenShiftControllerManagerLister interface {
	// List lists all OpenShiftControllerManagers in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*operatorv1.OpenShiftControllerManager, err error)
	// Get retrieves the OpenShiftControllerManager from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*operatorv1.OpenShiftControllerManager, error)
	OpenShiftControllerManagerListerExpansion
}

// openShiftControllerManagerLister implements the OpenShiftControllerManagerLister interface.
type openShiftControllerManagerLister struct {
	listers.ResourceIndexer[*operatorv1.OpenShiftControllerManager]
}

// NewOpenShiftControllerManagerLister returns a new OpenShiftControllerManagerLister.
func NewOpenShiftControllerManagerLister(indexer cache.Indexer) OpenShiftControllerManagerLister {
	return &openShiftControllerManagerLister{listers.New[*operatorv1.OpenShiftControllerManager](indexer, operatorv1.Resource("openshiftcontrollermanager"))}
}
