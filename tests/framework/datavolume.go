package framework

import (
	"kubevirt.io/containerized-data-importer/tests/utils"

	cdiv1 "kubevirt.io/containerized-data-importer/pkg/apis/datavolumecontroller/v1alpha1"
)

func (f *Framework) CreateDataVolumeFromDefinition(dataVolume *cdiv1.DataVolume) (*cdiv1.DataVolume, error) {
	return utils.CreateDataVolumeFromDefinition(f.CdiClient, f.Namespace.Name, dataVolume)
}

func (f *Framework) DeleteDataVolume(dataVolume *cdiv1.DataVolume) error {
	return utils.DeleteDataVolume(f.CdiClient, f.Namespace.Name, dataVolume)
}

func (f *Framework) WaitForDataVolumePhase(phase cdiv1.DataVolumePhase, dataVolumeName string) error {
	return utils.WaitForDataVolumePhase(f.CdiClient, f.Namespace.Name, phase, dataVolumeName)
}
