package coreos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"text/template"

	"github.com/Masterminds/semver"
	ctconfig "github.com/coreos/container-linux-config-transpiler/config"
	ignitionUtils "github.com/coreos/ignition/config/util"
	ignition "github.com/coreos/ignition/config/v2_1"
	ignitionTypes "github.com/coreos/ignition/config/v2_1/types"
	"github.com/golang/glog"
	"k8s.io/apimachinery/pkg/runtime"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	machinesv1alpha1 "github.com/kubermatic/machine-controller/pkg/machines/v1alpha1"
	"github.com/kubermatic/machine-controller/pkg/providerconfig"
	machinetemplate "github.com/kubermatic/machine-controller/pkg/template"
	"github.com/kubermatic/machine-controller/pkg/userdata/cloud"
	userdatahelper "github.com/kubermatic/machine-controller/pkg/userdata/helper"
)

func getConfig(r runtime.RawExtension) (*Config, error) {
	p := Config{}
	if len(r.Raw) == 0 {
		return &p, nil
	}

	if err := json.Unmarshal(r.Raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Config TODO
type Config struct {
	DisableAutoUpdate bool `json:"disableAutoUpdate"`
}

// Provider is a pkg/userdata.Provider implementation
type Provider struct{}

// SupportedContainerRuntimes return list of container runtimes
func (p Provider) SupportedContainerRuntimes() (runtimes []machinesv1alpha1.ContainerRuntimeInfo) {
	return []machinesv1alpha1.ContainerRuntimeInfo{
		{
			Name:    "docker",
			Version: "1.12",
		},
		{
			Name:    "docker",
			Version: "1.12.6",
		},
		{
			Name:    "docker",
			Version: "17.09",
		},
		{
			Name:    "docker",
			Version: "17.09.0",
		},
	}
}

// UserData renders user-data template
func (p Provider) UserData(
	spec machinesv1alpha1.MachineSpec,
	kubeconfig *clientcmdapi.Config,
	ccProvider cloud.ConfigProvider,
	clusterDNSIPs []net.IP,
) (string, error) {

	tmpl, err := template.New("user-data").Funcs(machinetemplate.TxtFuncMap()).Parse(ctTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse user-data template: %v", err)
	}

	kubeletVersion, err := semver.NewVersion(spec.Versions.Kubelet)
	if err != nil {
		return "", fmt.Errorf("invalid kubelet version: %v", err)
	}

	cpConfig, cpName, err := ccProvider.GetCloudConfig(spec)
	if err != nil {
		return "", fmt.Errorf("failed to get cloud config: %v", err)
	}

	pconfig, err := providerconfig.GetConfig(spec.ProviderConfig)
	if err != nil {
		return "", fmt.Errorf("failed to get provider config: %v", err)
	}

	if pconfig.OverwriteCloudConfig != nil {
		cpConfig = *pconfig.OverwriteCloudConfig
	}

	coreosConfig, err := getConfig(pconfig.OperatingSystemSpec)
	if err != nil {
		return "", fmt.Errorf("failed to get coreos config from provider config: %v", err)
	}

	kubeconfigString, err := userdatahelper.StringifyKubeconfig(kubeconfig)
	if err != nil {
		return "", err
	}

	kubernetesCACert, err := userdatahelper.GetCACert(kubeconfig)
	if err != nil {
		return "", fmt.Errorf("error extracting cacert: %v", err)
	}

	data := struct {
		MachineSpec       machinesv1alpha1.MachineSpec
		ProviderConfig    *providerconfig.Config
		CoreOSConfig      *Config
		Kubeconfig        string
		CloudProvider     string
		CloudConfig       string
		HyperkubeImageTag string
		ClusterDNSIPs     []net.IP
		KubernetesCACert  string
		JournaldMaxSize   string
	}{
		MachineSpec:       spec,
		ProviderConfig:    pconfig,
		CoreOSConfig:      coreosConfig,
		Kubeconfig:        kubeconfigString,
		CloudProvider:     cpName,
		CloudConfig:       cpConfig,
		HyperkubeImageTag: fmt.Sprintf("v%s", kubeletVersion.String()),
		ClusterDNSIPs:     clusterDNSIPs,
		KubernetesCACert:  kubernetesCACert,
		JournaldMaxSize:   userdatahelper.JournaldMaxUse,
	}
	b := &bytes.Buffer{}
	err = tmpl.Execute(b, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute user-data template: %v", err)
	}

	// Convert to ignition
	cfg, ast, report := ctconfig.Parse(b.Bytes())
	if len(report.Entries) > 0 {
		return "", fmt.Errorf("failed to validate coreos cloud config: %s", report.String())
	}

	ignCfg, report := ctconfig.Convert(cfg, "", ast)
	if len(report.Entries) > 0 {
		return "", fmt.Errorf("failed to convert container linux config to ignition: %s", report.String())
	}

	systemdUnitsData, err := systemdUnits(spec, cpName, coreosConfig, kubeletVersion, clusterDNSIPs)
	if err != nil {
		return "", fmt.Errorf("failed to generate systemd units data: %v", err)
	}

	iCfg := ignitionTypes.Config{
		Ignition: ignitionTypes.Ignition{
			Version: "2.1.0",
		},
		Passwd: ignitionTypes.Passwd{
			Users: []ignitionTypes.PasswdUser{
				{
					Name:              "core",
					SSHAuthorizedKeys: sshAuthorizedKeys(pconfig.SSHPublicKeys),
				},
			},
		},
		Networkd: networkdConfig(pconfig.Network),
		Systemd: ignitionTypes.Systemd{
			Units: systemdUnitsData,
		},
	}

	mergedConfig := ignition.Append(iCfg, ignCfg)
	validationReport := mergedConfig.Validate()

	if validationReport.IsFatal() {
		return "", fmt.Errorf("ignition config validation failed:\n%s", validationReport.String())
	}

	if len(validationReport.Entries) > 0 {
		glog.Warningf("ignition config validation:\n%s", validationReport.String())
	}

	out, err := json.MarshalIndent(mergedConfig, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal ignition config: %v", err)
	}

	return string(out), nil
}

func sshAuthorizedKeys(s []string) []ignitionTypes.SSHAuthorizedKey {
	k := make([]ignitionTypes.SSHAuthorizedKey, len(s))
	for i := 0; i < len(s); i++ {
		k[i] = ignitionTypes.SSHAuthorizedKey(s[i])
	}
	return k
}

func networkdConfig(n *providerconfig.NetworkConfig) ignitionTypes.Networkd {
	if n == nil {
		return ignitionTypes.Networkd{}
	}

	unitContents := fmt.Sprintf(`[Match]
# Because of difficulty predicting specific NIC names on different cloud providers,
# we only support static addressing on VSphere. There should be a single NIC attached
# that we will match by name prefix 'en' which denotes ethernet devices.
Name=en*

[Network]
DHCP=no
Address=%s
Gateway=%s
`, n.CIDR, n.Gateway)

	for _, dnsServer := range n.DNS.Servers {
		unitContents += fmt.Sprintf("DNS=%s\n", dnsServer)
	}

	return ignitionTypes.Networkd{
		Units: []ignitionTypes.Networkdunit{
			{
				Name:     "static-nic.network",
				Contents: unitContents,
			},
		},
	}
}

func kubeletService(spec machinesv1alpha1.MachineSpec, cpName string, kubeletVersion *semver.Version, clusterDNSIPs []net.IP) (string, error) {
	data := struct {
		MachineSpec       machinesv1alpha1.MachineSpec
		CloudProvider     string
		HyperkubeImageTag string
		ClusterDNSIPs     []net.IP
	}{
		MachineSpec:       spec,
		CloudProvider:     cpName,
		HyperkubeImageTag: fmt.Sprintf("v%s", kubeletVersion.String()),
		ClusterDNSIPs:     clusterDNSIPs,
	}

	kcTemplate := `[Unit]
Description=Kubernetes Kubelet
Requires=docker.service
After=docker.service
[Service]
TimeoutStartSec=5min
Environment=KUBELET_IMAGE=docker://k8s.gcr.io/hyperkube-amd64:{{ .HyperkubeImageTag }}
Environment="RKT_RUN_ARGS=--uuid-file-save=/var/cache/kubelet-pod.uuid \
  --insecure-options=image \
  --volume=resolv,kind=host,source=/etc/resolv.conf \
  --mount volume=resolv,target=/etc/resolv.conf \
  --volume cni-bin,kind=host,source=/opt/cni/bin \
  --mount volume=cni-bin,target=/opt/cni/bin \
  --volume cni-conf,kind=host,source=/etc/cni/net.d \
  --mount volume=cni-conf,target=/etc/cni/net.d \
  --volume etc-kubernetes,kind=host,source=/etc/kubernetes \
  --mount volume=etc-kubernetes,target=/etc/kubernetes \
  --volume var-log,kind=host,source=/var/log \
  --mount volume=var-log,target=/var/log \
  --volume var-lib-calico,kind=host,source=/var/lib/calico \
  --mount volume=var-lib-calico,target=/var/lib/calico"
ExecStartPre=/bin/mkdir -p /var/lib/calico
ExecStartPre=/bin/mkdir -p /etc/kubernetes/manifests
ExecStartPre=/bin/mkdir -p /etc/cni/net.d
ExecStartPre=/bin/mkdir -p /opt/cni/bin
ExecStartPre=-/usr/bin/rkt rm --uuid-file=/var/cache/kubelet-pod.uuid
ExecStart=/usr/lib/coreos/kubelet-wrapper \
  --container-runtime=docker \
  --allow-privileged=true \
  --cni-bin-dir=/opt/cni/bin \
  --cni-conf-dir=/etc/cni/net.d \
  --cluster-dns={{ ipSliceToCommaSeparatedString .ClusterDNSIPs }} \
  --cluster-domain=cluster.local \
  --authentication-token-webhook=true \
  --hostname-override={{ .MachineSpec.Name }} \
  --network-plugin=cni \
  {{- if .CloudProvider }}
  --cloud-provider={{ .CloudProvider }} \
  --cloud-config=/etc/kubernetes/cloud-config \
  {{- end }}
  --cert-dir=/etc/kubernetes/ \
  --pod-manifest-path=/etc/kubernetes/manifests \
  --resolv-conf=/etc/resolv.conf \
  --rotate-certificates=true \
  --kubeconfig=/etc/kubernetes/kubeconfig \
  --bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \
  --lock-file=/var/run/lock/kubelet.lock \
  --exit-on-lock-contention \
  --read-only-port=0 \
  --protect-kernel-defaults=true \
  --authorization-mode=Webhook \
  --anonymous-auth=false \
  --client-ca-file=/etc/kubernetes/ca.crt
ExecStop=-/usr/bin/rkt stop --uuid-file=/var/cache/kubelet-pod.uuid
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
`

	tmpl, err := template.New("kubeconfig.service").Funcs(machinetemplate.TxtFuncMap()).Parse(kcTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse user-data template: %v", err)
	}

	b := &bytes.Buffer{}
	err = tmpl.Execute(b, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute kubelet.service template: %v", err)
	}

	return b.String(), nil
}

func systemdUnits(spec machinesv1alpha1.MachineSpec, cpName string, coreosConfig *Config, kubeletVersion *semver.Version, clusterDNSIPs []net.IP) ([]ignitionTypes.Unit, error) {
	kubeletServiceContent, err := kubeletService(spec, cpName, kubeletVersion, clusterDNSIPs)
	if err != nil {
		return nil, err
	}

	var units []ignitionTypes.Unit

	if coreosConfig != nil && coreosConfig.DisableAutoUpdate {
		units = append(units,
			ignitionTypes.Unit{
				Name: "update-engine.service",
				Mask: true,
			},
			ignitionTypes.Unit{
				Name: "locksmithd.service",
				Mask: true,
			},
		)
	}

	units = append(units,
		ignitionTypes.Unit{
			Name:    "docker.service",
			Enabled: ignitionUtils.BoolToPtr(true),
		},
		ignitionTypes.Unit{
			Name:     "kubelet.service",
			Enabled:  ignitionUtils.BoolToPtr(true),
			Contents: kubeletServiceContent,
			Dropins: []ignitionTypes.Dropin{
				{
					Name:     "40-docker.conf",
					Contents: "[Unit]\nRequires=docker.service\nAfter=docker.service\n",
				},
			},
		},
	)

	return units, nil
}

const ctTemplate = `
storage:
  files:
    - path: "/etc/systemd/journald.conf.d/max_disk_use.conf"
      filesystem: root
      mode: 0644
      contents:
        inline: |
          [Journal]
          SystemMaxUse={{ .JournaldMaxSize }}

    - path: /etc/sysctl.d/k8s.conf
      filesystem: root
      mode: 0644
      contents:
        inline: |
          kernel.panic_on_oops = 1
          kernel.panic = 10
          vm.overcommit_memory = 1

    - path: /proc/sys/kernel/panic_on_oops
      filesystem: root
      mode: 0644
      contents:
        inline: |
          1

    - path: /proc/sys/kernel/panic
      filesystem: root
      mode: 0644
      contents:
        inline: |
          10

    - path: /proc/sys/vm/overcommit_memory
      filesystem: root
      mode: 0644
      contents:
        inline: |
          1

    - path: /etc/kubernetes/bootstrap.kubeconfig
      filesystem: root
      mode: 0400
      contents:
        inline: |
{{ .Kubeconfig | indent 10 }}

    - path: /etc/kubernetes/cloud-config
      filesystem: root
      mode: 0400
      contents:
        inline: |
{{ .CloudConfig | indent 10 }}

    - path: /etc/kubernetes/ca.crt
      filesystem: root
      mode: 0644
      contents:
        inline: |
{{ .KubernetesCACert | indent 10 }}

{{- if contains "1.12" .MachineSpec.Versions.ContainerRuntime.Version }}
    - path: /etc/coreos/docker-1.12
      mode: 0644
      filesystem: root
      contents:
        inline: |
          yes
{{ end }}

    - path: /etc/hostname
      filesystem: root
      mode: 0600
      contents:
        inline: '{{ .MachineSpec.Name }}'

    - path: /etc/ssh/sshd_config
      filesystem: root
      mode: 0600
      user:
        id: 0
      group:
        id: 0
      contents:
        inline: |
          # Use most defaults for sshd configuration.
          Subsystem sftp internal-sftp
          ClientAliveInterval 180
          UseDNS no
          UsePAM yes
          PrintLastLog no # handled by PAM
          PrintMotd no # handled by PAM
          PasswordAuthentication no
          ChallengeResponseAuthentication no
`
