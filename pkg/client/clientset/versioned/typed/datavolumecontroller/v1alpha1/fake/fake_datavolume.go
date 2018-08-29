/*
Copyright 2018 The CDI Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1alpha1 "kubevirt.io/containerized-data-importer/pkg/apis/datavolumecontroller/v1alpha1"
)

// FakeDataVolumes implements DataVolumeInterface
type FakeDataVolumes struct {
	Fake *FakeCdiV1alpha1
	ns   string
}

var datavolumesResource = schema.GroupVersionResource{Group: "cdi.kubevirt.io", Version: "v1alpha1", Resource: "datavolumes"}

var datavolumesKind = schema.GroupVersionKind{Group: "cdi.kubevirt.io", Version: "v1alpha1", Kind: "DataVolume"}

// Get takes name of the dataVolume, and returns the corresponding dataVolume object, and an error if there is any.
func (c *FakeDataVolumes) Get(name string, options v1.GetOptions) (result *v1alpha1.DataVolume, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(datavolumesResource, c.ns, name), &v1alpha1.DataVolume{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.DataVolume), err
}

// List takes label and field selectors, and returns the list of DataVolumes that match those selectors.
func (c *FakeDataVolumes) List(opts v1.ListOptions) (result *v1alpha1.DataVolumeList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(datavolumesResource, datavolumesKind, c.ns, opts), &v1alpha1.DataVolumeList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.DataVolumeList{}
	for _, item := range obj.(*v1alpha1.DataVolumeList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested dataVolumes.
func (c *FakeDataVolumes) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(datavolumesResource, c.ns, opts))

}

// Create takes the representation of a dataVolume and creates it.  Returns the server's representation of the dataVolume, and an error, if there is any.
func (c *FakeDataVolumes) Create(dataVolume *v1alpha1.DataVolume) (result *v1alpha1.DataVolume, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(datavolumesResource, c.ns, dataVolume), &v1alpha1.DataVolume{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.DataVolume), err
}

// Update takes the representation of a dataVolume and updates it. Returns the server's representation of the dataVolume, and an error, if there is any.
func (c *FakeDataVolumes) Update(dataVolume *v1alpha1.DataVolume) (result *v1alpha1.DataVolume, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(datavolumesResource, c.ns, dataVolume), &v1alpha1.DataVolume{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.DataVolume), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeDataVolumes) UpdateStatus(dataVolume *v1alpha1.DataVolume) (*v1alpha1.DataVolume, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(datavolumesResource, "status", c.ns, dataVolume), &v1alpha1.DataVolume{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.DataVolume), err
}

// Delete takes name of the dataVolume and deletes it. Returns an error if one occurs.
func (c *FakeDataVolumes) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(datavolumesResource, c.ns, name), &v1alpha1.DataVolume{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeDataVolumes) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(datavolumesResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.DataVolumeList{})
	return err
}

// Patch applies the patch and returns the patched dataVolume.
func (c *FakeDataVolumes) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.DataVolume, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(datavolumesResource, c.ns, name, data, subresources...), &v1alpha1.DataVolume{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.DataVolume), err
}
