package main

import "strings"

type IacAndContainerManifest struct {
ServiceName              string
DockerfileBaseImage      string
DockerfileUser           string
K8sPrivileged            bool
K8sReadOnlyRootFS        bool
TerraformS3PublicAcl     bool
TerraformSecurityGroup00 bool
}

type SdlcReleaseGateResult struct {
ServiceName        string
PassedReleaseGate  bool
Misconfigurations  []string
WizPolicyAlignment string
}

func EvaluatePreProdIacAndContainer(m IacAndContainerManifest) SdlcReleaseGateResult {
var issues []string

if strings.HasSuffix(m.DockerfileBaseImage, ":latest") || !strings.Contains(m.DockerfileBaseImage, "@sha256:") {
issues = append(issues, "CONTAINER_UNPINNED_IMAGE_TAG: Base image must be pinned to an immutable SHA-256 digest")
}
if m.DockerfileUser == "" || m.DockerfileUser == "root" || m.DockerfileUser == "0" {
issues = append(issues, "CONTAINER_ROOT_USER: Container must specify non-root USER directive")
}
if m.K8sPrivileged {
issues = append(issues, "K8S_PRIVILEGED_POD: securityContext.privileged=true is forbidden")
}
if !m.K8sReadOnlyRootFS {
issues = append(issues, "K8S_WRITABLE_ROOTFS: securityContext.readOnlyRootFilesystem must be true")
}
if m.TerraformS3PublicAcl {
issues = append(issues, "IAC_S3_PUBLIC_ACL: Terraform aws_s3_bucket allows public read/write ACL")
}
if m.TerraformSecurityGroup00 {
issues = append(issues, "IAC_OPEN_INGRESS_0_0_0_0: Security group exposes sensitive port to 0.0.0.0/0")
}

passed := len(issues) == 0
alignment := "WIZ_CLOUD_AND_IAC_BENCHMARK_COMPLIANT"
if !passed {
alignment = "BLOCKED_PRE_PRODUCTION_MISCONFIGURATION"
}

return SdlcReleaseGateResult{
ServiceName:        m.ServiceName,
PassedReleaseGate:  passed,
Misconfigurations:  issues,
WizPolicyAlignment: alignment,
}
}
