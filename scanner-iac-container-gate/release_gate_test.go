package main

import "testing"

func TestEvaluatePreProdIacAndContainerBlocksMisconfiguredManifest(t *testing.T) {
insecure := IacAndContainerManifest{
ServiceName:              "payment-processor",
DockerfileBaseImage:      "python:3.11:latest",
DockerfileUser:           "root",
K8sPrivileged:            true,
K8sReadOnlyRootFS:        false,
TerraformS3PublicAcl:     true,
TerraformSecurityGroup00: true,
}

res := EvaluatePreProdIacAndContainer(insecure)
if res.PassedReleaseGate {
t.Fatal("Expected misconfigured IaC and container manifest to be blocked at release gate")
}
if len(res.Misconfigurations) != 6 {
t.Fatalf("Expected 6 misconfigurations, got %d", len(res.Misconfigurations))
}
}

func TestEvaluatePreProdIacAndContainerApprovesHardenedManifest(t *testing.T) {
hardened := IacAndContainerManifest{
ServiceName:              "payment-processor",
DockerfileBaseImage:      "cgr.dev/chainguard/python@sha256:99aabbccddeeff",
DockerfileUser:           "65532",
K8sPrivileged:            false,
K8sReadOnlyRootFS:        true,
TerraformS3PublicAcl:     false,
TerraformSecurityGroup00: false,
}

res := EvaluatePreProdIacAndContainer(hardened)
if !res.PassedReleaseGate || len(res.Misconfigurations) != 0 {
t.Fatalf("Expected hardened manifest to pass release gate, got %+v", res)
}
}
