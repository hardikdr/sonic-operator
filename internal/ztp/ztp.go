// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package ztp

import (
	"embed"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkingv1alpha1 "github.com/ironcore-dev/sonic-operator/api/v1alpha1"
)

//go:embed templates
var templateFS embed.FS

type SwitchType string

const (
	SwitchTypeLeaf  SwitchType = "leaf"
	SwitchTypeSpine SwitchType = "spine"
)

type Config struct {
	// SearchDomain works like this:
	//
	//   $zone.infra.$environment.ironcore.dev
	//
	// Where zone is the region and availability zone, e.g. wdf-a; and
	// environment is one of dev, staging, canary, or live.
	//
	// Based on the type and ID each device will get a name such as spine-2 or
	// oob-leaf-1 to create FQDNs like this:
	//
	//   spine-2.region-b.infra.staging.ironcore.dev
	//
	// which uniqely identifies each device.
	SearchDomain string `json:"searchDomain"`
	// DHCPServerAddr for the relay to send DHCP packets to.
	//
	// Example:
	//
	//   2001:db8::547
	DHCPServerAddr string                          `json:"dhcpServerAddr"`
	SwitchParams   map[netip.Addr]SwitchParameters `json:"switchParams"`
}

type SwitchParameters struct {
	Type SwitchType `json:"type"`
	ID   int        `json:"id"`
	// Prefix must be a /64 for this sepcific switch.
	//
	// Example:
	//
	//   2001:db8::/64
	Prefix netip.Prefix `json:"prefix"`
	// IP should be the first /128 of the Prefix above.
	//
	// Example:
	//
	//   2001:db8::/128
	IP       netip.Prefix `json:"ip"`
	ASNumber int          `json:"asNumber"`
}

type handler struct {
	t *template.Template
	m map[netip.Addr]SwitchParameters
}

type configMapHandler struct {
	reader client.Reader
}

type generatedHandler struct {
	reader                    client.Reader
	controlKubeconfigFilePath string
}

// GeneratedOptions configures declarative, Switch-backed ZTP rendering.
type GeneratedOptions struct {
	// ControlKubeconfigFile is an optional kubeconfig mounted into the operator
	// pod. It is injected only into generated bootstrap containers that
	// explicitly opt in.
	ControlKubeconfigFile string
}

func Register(mux *http.ServeMux, c Config) {
	t := template.New("ztp-scripts")
	t = t.Funcs(template.FuncMap{
		"add":             func(a, b int) int { return a + b },
		"dhcpServerAddr":  func() string { return c.DHCPServerAddr },
		"searchDomain":    func() string { return c.SearchDomain },
		"interfacePrefix": interfacePrefix,
	})
	t = template.Must(t.ParseFS(templateFS, "templates/*.gotmpl"))

	mux.Handle("GET /ztp", &handler{t: t, m: c.SwitchParams})
}

// RegisterConfigMap serves the script referenced by the Switch whose ZTP
// source address matches the requesting client. It deliberately has no
// template fallback: configmap mode must fail closed.
func RegisterConfigMap(mux *http.ServeMux, reader client.Reader) {
	mux.Handle("GET /ztp", &configMapHandler{reader: reader})
}

// RegisterGenerated renders a complete ZTP script from the matching Switch
// object. Unlike configmap mode, no user-provided ZTP script is read or
// modified.
func RegisterGenerated(mux *http.ServeMux, reader client.Reader, options GeneratedOptions) {
	mux.Handle("GET /ztp", &generatedHandler{
		reader:                    reader,
		controlKubeconfigFilePath: options.ControlKubeconfigFile,
	})
}

// interfacePrefix takes the interface ID and the /64 prefix of the switch and
// reserves a unique /112 prefix for each interface based on the interface ID.
func interfacePrefix(prefix netip.Prefix, interfaceID int) (string, error) {
	if prefix.Bits() != 64 {
		return "", fmt.Errorf("unexpected prefix size %d, want 64", prefix.Bits())
	}

	b := prefix.Addr().AsSlice()
	b[13] = byte(interfaceID) + 1

	a, _ := netip.AddrFromSlice(b)

	prefix = netip.PrefixFrom(a, 112)
	return prefix.String(), nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		handleErr(w, err)
		return
	}

	c, ok := h.m[ap.Addr()]
	if !ok {
		handleErr(w, fmt.Errorf("unknown ip '%s'", ap.Addr().String()))
		return
	}

	switch c.Type {
	case SwitchTypeLeaf:
		err = h.t.ExecuteTemplate(w, "leaf.sh.gotmpl", c)
	case SwitchTypeSpine:
		err = h.t.ExecuteTemplate(w, "spine.sh.gotmpl", c)
	}
	if err != nil {
		handleErr(w, err)
		return
	}
}

func (h *configMapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	matched, err := matchingSwitch(r, h.reader)
	if err != nil {
		handleErr(w, err)
		return
	}
	if matched.Spec.ZTP.ScriptRef == nil {
		handleErr(w, fmt.Errorf("switch %q has no ztp.scriptRef for configmap mode", matched.Name))
		return
	}

	ref := matched.Spec.ZTP.ScriptRef
	configMap := &corev1.ConfigMap{}
	if err := h.reader.Get(r.Context(), types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, configMap); err != nil {
		handleErr(w, fmt.Errorf("getting ZTP ConfigMap %s/%s: %w", ref.Namespace, ref.Name, err))
		return
	}
	script, ok := configMap.Data[ref.Key]
	if !ok {
		handleErr(w, fmt.Errorf("ZTP ConfigMap %s/%s has no key %q", ref.Namespace, ref.Name, ref.Key))
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	if _, err := fmt.Fprint(w, script); err != nil {
		slog.Error("failed to write ZTP ConfigMap script", "switch", matched.Name, "err", err)
	}
}

func (h *generatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	matched, err := matchingSwitch(r, h.reader)
	if err != nil {
		handleErr(w, err)
		return
	}

	script, err := renderGeneratedScript(matched, h.controlKubeconfigFilePath)
	if err != nil {
		handleErr(w, fmt.Errorf("rendering generated ZTP for switch %q: %w", matched.Name, err))
		return
	}

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	if _, err := fmt.Fprint(w, script); err != nil {
		slog.Error("failed to write generated ZTP script", "switch", matched.Name, "err", err)
	}
}

func matchingSwitch(r *http.Request, reader client.Reader) (*networkingv1alpha1.Switch, error) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}

	switches := &networkingv1alpha1.SwitchList{}
	if err := reader.List(r.Context(), switches); err != nil {
		return nil, fmt.Errorf("listing switches for ZTP: %w", err)
	}

	var matched *networkingv1alpha1.Switch
	for i := range switches.Items {
		switchConfig := switches.Items[i].Spec.ZTP
		if switchConfig == nil {
			continue
		}
		configuredAddr, err := netip.ParseAddr(switchConfig.SourceAddress)
		if err != nil {
			return nil, fmt.Errorf("switch %q has invalid ZTP source address %q: %w", switches.Items[i].Name, switchConfig.SourceAddress, err)
		}
		if configuredAddr != ap.Addr() {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("multiple switches use ZTP source address %q", ap.Addr())
		}
		matched = &switches.Items[i]
	}
	if matched == nil {
		return nil, fmt.Errorf("no switch configured for ZTP source address %q", ap.Addr())
	}
	return matched, nil
}

func renderGeneratedScript(switchObject *networkingv1alpha1.Switch, controlKubeconfigFilePath string) (string, error) {
	hostname := switchObject.Spec.Hostname
	if hostname == "" {
		hostname = switchObject.Name
	}
	if hostname == "" {
		return "", fmt.Errorf("hostname is empty")
	}

	var b strings.Builder
	b.WriteString("#!/bin/bash\n")
	b.WriteString("set -euo pipefail\n\n")
	b.WriteString("# Generated by sonic-operator ")
	b.WriteString(shellQuote(switchObject.Name))
	b.WriteString("\n")

	// Apply boot lifecycle intent before any fallible switch configuration or
	// bootstrap workload operation. This is intentionally strict: a failure to
	// persist the requested next boot mode must not be hidden.
	switch switchObject.Spec.NextBootMode {
	case "", networkingv1alpha1.NextBootModeNone:
	case networkingv1alpha1.NextBootModeInstallOS:
		appendONIEInstallBootConfig(&b)
	default:
		return "", fmt.Errorf("unsupported next boot mode %q", switchObject.Spec.NextBootMode)
	}

	b.WriteString("config hostname ")
	b.WriteString(shellQuote(hostname))
	b.WriteString("\n")
	b.WriteString("config save -y\n")

	if switchObject.Spec.Bootstrap != nil && len(switchObject.Spec.Bootstrap.Containers) > 0 {
		containers := switchObject.Spec.Bootstrap.Containers
		needsControlKubeconfig := false
		for _, container := range containers {
			if container.InjectControlKubeconfig {
				needsControlKubeconfig = true
				break
			}
		}

		b.WriteString("\n# sonic-operator bootstrap containers\n")

		var encodedControlKubeconfig string
		if needsControlKubeconfig {
			if controlKubeconfigFilePath == "" {
				return "", fmt.Errorf("injectControlKubeconfig requires --bootstrap-control-kubeconfig-file")
			}
			kubeconfig, err := os.ReadFile(controlKubeconfigFilePath)
			if err != nil {
				return "", fmt.Errorf("reading control kubeconfig file %q: %w", controlKubeconfigFilePath, err)
			}

			encodedControlKubeconfig = base64.StdEncoding.EncodeToString(kubeconfig)
		}

		for _, container := range containers {
			dockerUser, err := bootstrapContainerDockerUser(container)
			if err != nil {
				return "", err
			}

			controlKubeconfigPath := ""
			if container.InjectControlKubeconfig {
				if container.SecurityContext == nil || container.SecurityContext.RunAsUser == nil {
					return "", fmt.Errorf("bootstrap container %q injects the control kubeconfig but has no securityContext.runAsUser", container.Name)
				}
				controlKubeconfigPath = "/etc/sonic-operator/credentials/" + container.Name + "/control-kubeconfig"
			}

			// A workload is best effort. Its failure must not prevent later
			// containers from being attempted or obscure the already-applied boot
			// lifecycle configuration above.
			b.WriteString("if ! (\n")
			if container.InjectControlKubeconfig {
				b.WriteString("install -d -m 0700 /etc/sonic-operator/credentials &&\n")
				b.WriteString("install -d -m 0700 ")
				b.WriteString(shellQuote("/etc/sonic-operator/credentials/" + container.Name))
				b.WriteString(" &&\n")
				b.WriteString("printf '%s' ")
				b.WriteString(shellQuote(encodedControlKubeconfig))
				b.WriteString(" | base64 -d >")
				b.WriteString(shellQuote(controlKubeconfigPath))
				b.WriteString(" &&\n")
				b.WriteString("chown ")
				b.WriteString(dockerUser)
				b.WriteByte(' ')
				b.WriteString(shellQuote(controlKubeconfigPath))
				b.WriteString(" &&\n")
				b.WriteString("chmod 0600 ")
				b.WriteString(shellQuote(controlKubeconfigPath))
				b.WriteString(" &&\n")
			}

			b.WriteString("docker pull ")
			b.WriteString(shellQuote(container.Image))
			b.WriteString(" &&\n")
			b.WriteString("(docker rm -f ")
			b.WriteString(shellQuote(container.Name))
			b.WriteString(" >/dev/null 2>&1 || true) &&\n")
			b.WriteString("docker run -d --name ")
			b.WriteString(shellQuote(container.Name))
			b.WriteString(" --network host --restart unless-stopped")
			if dockerUser != "" {
				b.WriteString(" --user ")
				b.WriteString(shellQuote(dockerUser))
			}
			if container.InjectControlKubeconfig {
				b.WriteString(" -e KUBECONFIG=/var/run/sonic-operator/control-kubeconfig")
				b.WriteString(" -v ")
				b.WriteString(shellQuote(controlKubeconfigPath + ":/var/run/sonic-operator/control-kubeconfig:ro"))
			}
			b.WriteByte(' ')
			b.WriteString(shellQuote(container.Image))
			for _, command := range container.Command {
				b.WriteByte(' ')
				b.WriteString(shellQuote(command))
			}
			for _, arg := range container.Args {
				b.WriteByte(' ')
				b.WriteString(shellQuote(arg))
			}
			b.WriteString("\n); then\n")
			b.WriteString("  echo ")
			b.WriteString(shellQuote("sonic-operator: bootstrap container " + container.Name + " failed; continuing"))
			b.WriteString(" >&2\nfi\n")
		}
	}

	b.WriteString("sync\n")
	return b.String(), nil
}

func bootstrapContainerDockerUser(container networkingv1alpha1.BootstrapContainer) (string, error) {
	if container.SecurityContext == nil {
		return "", nil
	}

	securityContext := container.SecurityContext
	if securityContext.RunAsGroup != nil && securityContext.RunAsUser == nil {
		return "", fmt.Errorf("bootstrap container %q sets securityContext.runAsGroup without securityContext.runAsUser", container.Name)
	}
	if securityContext.RunAsUser == nil {
		return "", nil
	}

	user := strconv.FormatInt(*securityContext.RunAsUser, 10)
	if securityContext.RunAsGroup == nil {
		return user, nil
	}
	return user + ":" + strconv.FormatInt(*securityContext.RunAsGroup, 10), nil
}

func appendONIEInstallBootConfig(b *strings.Builder) {
	b.WriteString(`
# Configure ONIE install discovery for the next and every subsequent SONiC reboot.
mkdir -p /onieboot
cat >/etc/systemd/system/onieboot.mount <<'EOF'
[Unit]
Description=ONIE boot partition

[Mount]
What=LABEL=ONIE-BOOT
Where=/onieboot
Type=auto
Options=defaults

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/sonic-operator-onie-install.service <<'EOF'
[Unit]
Description=Configure next boot for ONIE install discovery
Requires=onieboot.mount
After=onieboot.mount

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'grub-editenv /host/grub/grubenv set next_entry=ONIE'
ExecStart=/bin/sh -c 'grub-editenv /onieboot/grub/grubenv set onie_mode=install'

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now onieboot.mount
systemctl enable --now sonic-operator-onie-install.service
`)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\\"'\\\"'") + "'"
}

func handleErr(w http.ResponseWriter, e error) {
	w.WriteHeader(http.StatusInternalServerError)
	_, err := fmt.Fprint(w, e.Error())
	if err != nil {
		slog.Error("failed to write back previous error", "e", e, "err", err)
	}
}
