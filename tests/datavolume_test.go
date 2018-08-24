package tests_test

import (
	"flag"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kubevirt.io/containerized-data-importer/tests/framework"
	"kubevirt.io/containerized-data-importer/tests/utils"

	cdiv1 "kubevirt.io/containerized-data-importer/pkg/apis/datavolumecontroller/v1alpha1"
)

var _ = Describe("DataVolume tests", func() {
	flag.Parse()

	f, err := framework.NewFramework("dv-func-test", &framework.Config{})
	if err != nil {
		Fail("Unable to create framework struct")
	}

	Describe("Verify DataVolume", func() {
		It("create and import should succeed", func() {
			dataVolume := utils.NewDataVolumeWithHttpImport("test-dv1", "1Gi", utils.TinyCoreIsoURL)
			By("creating new datavolume")
			dataVolume, err := f.CreateDataVolumeFromDefinition(dataVolume)
			Expect(err).To(BeNil())

			By("waiting for datavolume to succeed")
			f.WaitForDataVolumePhase(cdiv1.Succeeded, dataVolume.Name)

			// verify PVC was created
			By("verifying pvc was created")
			_, err = f.K8sClient.CoreV1().PersistentVolumeClaims(dataVolume.Namespace).Get(dataVolume.Name, metav1.GetOptions{})
			Expect(err).To(BeNil())

			err = f.DeleteDataVolume(dataVolume)
			Expect(err).To(BeNil())
		}, 45)

		It("create and import should fail if invalid url provided", func() {
			dataVolume := utils.NewDataVolumeWithHttpImport("test-dv2", "1Gi", "http://i-made-this-up.kube-system/tinyCore.iso")

			By("creating new datavolume")
			dataVolume, err := f.CreateDataVolumeFromDefinition(dataVolume)
			Expect(err).To(BeNil())

			By("waiting for datavolume to fail")
			f.WaitForDataVolumePhase(cdiv1.Failed, dataVolume.Name)

			// verify PVC was created
			By("verifying pvc was created")
			_, err = f.K8sClient.CoreV1().PersistentVolumeClaims(dataVolume.Namespace).Get(dataVolume.Name, metav1.GetOptions{})
			Expect(err).To(BeNil())

			err = f.DeleteDataVolume(dataVolume)
			Expect(err).To(BeNil())
		}, 45)
	})
})
