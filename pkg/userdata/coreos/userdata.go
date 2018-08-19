package coreos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"text/template"

	"github.com/Masterminds/semver"
	ignitionUtils "github.com/coreos/ignition/config/util"
	ignitionTypes "github.com/coreos/ignition/config/v2_1/types"
	"github.com/golang/glog"
	"github.com/vincent-petithory/dataurl"
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

	systemdUnitsData, err := systemdUnits(spec, cpName, coreosConfig, clusterDNSIPs)
	if err != nil {
		return "", fmt.Errorf("failed to generate systemd units data: %v", err)
	}

	ignCfg := ignitionTypes.Config{
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
		Storage: ignitionTypes.Storage{
			Files: getFileEntries(kubeconfigString, cpConfig, kubernetesCACert, spec),
		},
	}

	if validationReport := ignCfg.Validate(); len(validationReport.Entries) > 0 {
		glog.Warningf("ignition config validation failed:\n%s", validationReport.String())
	}

	out, err := json.MarshalIndent(ignCfg, "", "  ")
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

func getFileEntries(kubeconfigString, cpConfig, kubernetesCACert string, machineSpec machinesv1alpha1.MachineSpec) []ignitionTypes.File {
	files := []ignitionTypes.File{
		encodeFile("/etc/systemd/journald.conf.d/max_disk_use.conf", "root", 0644, fmt.Sprintf(`[Journal]
SystemMaxUse=%s
`, userdatahelper.JournaldMaxUse)),
		encodeFile("/etc/sysctl.d/k8s.conf", "root", 0644, `kernel.panic_on_oops = 1
kernel.panic = 10
vm.overcommit_memory = 1
`),
		encodeFile("/proc/sys/kernel/panic_on_oops", "root", 0644, "1\n"),
		encodeFile("/proc/sys/kernel/panic", "root", 0644, "10\n"),
		encodeFile("/proc/sys/vm/overcommit_memory", "root", 0644, "1\n"),
		encodeFile("/etc/kubernetes/bootstrap.kubeconfig", "root", 0400, kubeconfigString),
		encodeFile("/etc/kubernetes/cloud-config", "root", 0400, cpConfig+"\n"),   // the endline is there to perfectly preserve previous formatting
		encodeFile("/etc/kubernetes/ca.crt", "root", 0644, kubernetesCACert+"\n"), // dito
	}

	if strings.Contains(machineSpec.Versions.ContainerRuntime.Version, "1.12") {
		files = append(files,
			encodeFile("/etc/coreos/docker-1.12", "root", 0644, "yes\n"),
		)
	}

	files = append(files,
		encodeFile("/etc/hostname", "root", 0600, machineSpec.Name),
		encodeFileOwnedByRoot("/etc/ssh/sshd_config", "root", 0600, `# Use most defaults for sshd configuration.
Subsystem sftp internal-sftp
ClientAliveInterval 180
UseDNS no
UsePAM yes
PrintLastLog no # handled by PAM
PrintMotd no # handled by PAM
PasswordAuthentication no
ChallengeResponseAuthentication no
`),
	)

	return files
}

func encodeFile(path, filesystem string, mode int, content string) ignitionTypes.File {
	return ignitionTypes.File{
		Node: ignitionTypes.Node{
			Path:       path,
			Filesystem: filesystem,
		},
		FileEmbedded1: ignitionTypes.FileEmbedded1{
			Mode: mode,
			Contents: ignitionTypes.FileContents{
				Source: "data:," + dataurl.EscapeString(content),
			},
		},
	}
}

func encodeFileOwnedByRoot(path, filesystem string, mode int, content string) ignitionTypes.File {
	file := encodeFile(path, filesystem, mode, content)
	file.Node.User = ignitionTypes.NodeUser{ID: ignitionUtils.IntToPtr(0)}
	file.Node.Group = ignitionTypes.NodeGroup{ID: ignitionUtils.IntToPtr(0)}
	return file
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

func systemdUnits(spec machinesv1alpha1.MachineSpec, cpName string, coreosConfig *Config, clusterDNSIPs []net.IP) ([]ignitionTypes.Unit, error) {
	kubeletVersion, err := semver.NewVersion(spec.Versions.Kubelet)
	if err != nil {
		return nil, fmt.Errorf("invalid kubelet version: %v", err)
	}

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
