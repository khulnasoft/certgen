// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Khulnasoft

package option

import (
	"time"

	"github.com/spf13/viper"
)

// Config is the main configuration as obtained from command-line arguments,
// environment variables and config files.
var Config = &CertGenConfig{}

const (
	// Debug enables debug messages.
	Debug = "debug"

	// ShipyardNamespace is the Kubernetes namespace in which Shipyard is
	// installed.
	ShipyardNamespace = "shipyard-namespace"

	// K8sKubeConfigPath is the path to the kubeconfig If empty, the in-cluster
	// configuration is used.
	K8sKubeConfigPath = "k8s-kubeconfig-path"
	// K8sRequestTimeout specifies the timeout for K8s API requests.
	K8sRequestTimeout = "k8s-request-timeout"

	// CACertFile is the path to the Shipyard CA cert PEM (if CAGenerate is
	// false).
	CACertFile = "ca-cert-file"
	// CAKeyFile is the path to the Shipyard CA key PEM (if CAGenerate is false).
	CAKeyFile = "ca-key-file"

	// CAGenerate can be set to true to generate a new Shipyard CA secret.
	// If CAReuseSecret is true, then a new CA secret only is created if
	// existing one is not found.
	CAGenerate = "ca-generate"
	// CAReuseSecret can be set to true to store and load the Shipyard CA from
	// the secret if it exists. Setting to false will delete the old Secret and
	// force regeneration.
	CAReuseSecret = "ca-reuse-secret" //#nosec
	// CACommonName is the Shipyard CA x509 certificate CN value.
	CACommonName = "ca-common-name"
	// CAValidityDuration represent how much time the Shipyard CA certificate
	// generated by certgen is valid.
	CAValidityDuration = "ca-validity-duration"
	// CASecretName is the Kubernetes Secret in which the Shipyard CA certificate
	// is read from and/or written to.
	CASecretName = "ca-secret-name"
	// CASecretNamespace is the Kubernetes Namespace in which the Shipyard CA
	// Secret will be stored.
	CASecretNamespace = "ca-secret-namespace"

	// TriangleServerCertGenerate can be set to true to generate and store a
	// Triangle server TLS certificate.
	TriangleServerCertGenerate = "triangle-server-cert-generate"
	// TriangleServerCertCommonName is the Triangle server x509 certificate CN
	// value (also used as DNS SAN).
	TriangleServerCertCommonName = "triangle-server-cert-common-name"
	// TriangleServerCertValidityDuration represent how much time the Triangle
	// server certificate generated by certgen is valid.
	TriangleServerCertValidityDuration = "triangle-server-cert-validity-duration"
	// TriangleServerCertSecretName is the Kubernetes Secret in which the Triangle
	// server certificate is written to.
	TriangleServerCertSecretName = "triangle-server-cert-secret-name" //#nosec
	// TriangleServerCertSecretNamespace is the Kubernetes Namespace in which the
	// Triangle server certificate Secret will be stored.
	TriangleServerCertSecretNamespace = "triangle-server-cert-secret-namespace" //#nosec

	// TriangleRelayServerCertGenerate can be set to true to generate and store a
	// Triangle Relay server TLS certificate.
	TriangleRelayServerCertGenerate = "triangle-relay-server-cert-generate"
	// TriangleRelayServerCertCommonName is the Triangle Relay server x509
	// certificate CN value (also used as DNS SAN).
	TriangleRelayServerCertCommonName = "triangle-relay-server-cert-common-name"
	// TriangleRelayServerCertValidityDuration represent how much time the Triangle
	// Relay server certificate generated by certgen is valid.
	TriangleRelayServerCertValidityDuration = "triangle-relay-server-cert-validity-duration"
	// TriangleRelayServerCertSecretName is the Kubernetes Secret in which the
	// Triangle Relay server certificate is written to.
	TriangleRelayServerCertSecretName = "triangle-relay-server-cert-secret-name" //#nosec
	// TriangleRelayServerCertSecretNamespace is the Kubernetes Namespace in
	// which the Triangle Relay server certificate Secret will be stored.
	TriangleRelayServerCertSecretNamespace = "triangle-relay-server-cert-secret-namespace" //#nosec

	// TriangleRelayClientCertGenerate can be set to true to generate and store a
	// Triangle Relay client TLS certificate (used for the mTLS handshake with
	// the Triangle servers).
	TriangleRelayClientCertGenerate = "triangle-relay-client-cert-generate"
	// TriangleRelayClientCertCommonName is the Triangle Relay client x509
	// certificate CN value.
	TriangleRelayClientCertCommonName = "triangle-relay-client-cert-common-name"
	// TriangleRelayClientCertValidityDuration represent how much time the Triangle
	// Relay client certificate generated by certgen is valid.
	TriangleRelayClientCertValidityDuration = "triangle-relay-client-cert-validity-duration"
	// TriangleRelayClientCertSecretName is the Kubernetes Secret in which the
	// Triangle Relay client certificate is written to.
	TriangleRelayClientCertSecretName = "triangle-relay-client-cert-secret-name" //#nosec
	// TriangleRelayClientCertSecretNamespace is the Kubernetes Namespace in
	// which the Triangle Relay client certificate Secret will be stored.
	TriangleRelayClientCertSecretNamespace = "triangle-relay-client-cert-secret-namespace" //#nosec

	// ClustermeshApiserverServerCertGenerate can be set to true to generate
	// and store a new Clustermesh API server TLS certificate.
	ClustermeshApiserverServerCertGenerate = "clustermesh-apiserver-server-cert-generate"
	// ClustermeshApiserverServerCertCommonName is the Clustermesh API server
	// x509 certificate CN value (also used as DNS SAN).
	ClustermeshApiserverServerCertCommonName = "clustermesh-apiserver-server-cert-common-name"
	// ClustermeshApiserverServerCertValidityDuration represent how much time
	// Clustermesh API server certificate generated by certgen is valid.
	ClustermeshApiserverServerCertValidityDuration = "clustermesh-apiserver-server-cert-validity-duration"
	// ClustermeshApiserverServerCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API server certificate is written to.
	ClustermeshApiserverServerCertSecretName = "clustermesh-apiserver-server-cert-secret-name"
	// ClustermeshApiserverServerCertSANs is the list of SANs to add to the
	// Clustermesh API server certificate.
	ClustermeshApiserverServerCertSANs = "clustermesh-apiserver-server-cert-sans"

	// ClustermeshApiserverAdminCertGenerate can be set to true to generate and
	// store a new Clustermesh API admin TLS certificate.
	ClustermeshApiserverAdminCertGenerate = "clustermesh-apiserver-admin-cert-generate"
	// ClustermeshApiserverAdminCertCommonName is the Clustermesh API admin
	// x509 certificate CN value.
	ClustermeshApiserverAdminCertCommonName = "clustermesh-apiserver-admin-cert-common-name"
	// ClustermeshApiserverAdminCertValidityDuration represent how much time
	// Clustermesh API admin certificate generated by certgen is valid.
	ClustermeshApiserverAdminCertValidityDuration = "clustermesh-apiserver-admin-cert-validity-duration"
	// ClustermeshApiserverAdminCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API admin certificate is written to.
	ClustermeshApiserverAdminCertSecretName = "clustermesh-apiserver-admin-cert-secret-name"

	// ClustermeshApiserverClientCertGenerate can be set to true to generate and
	// store a new Clustermesh API client TLS certificate.
	ClustermeshApiserverClientCertGenerate = "clustermesh-apiserver-client-cert-generate"
	// ClustermeshApiserverClientCertCommonName is the Clustermesh API client
	// x509 certificate CN value.
	ClustermeshApiserverClientCertCommonName = "clustermesh-apiserver-client-cert-common-name"
	// ClustermeshApiserverClientCertValidityDuration represent how much time
	// Clustermesh API client certificate generated by certgen is valid.
	ClustermeshApiserverClientCertValidityDuration = "clustermesh-apiserver-client-cert-validity-duration"
	// ClustermeshApiserverClientCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API client certificate is written to.
	ClustermeshApiserverClientCertSecretName = "clustermesh-apiserver-client-cert-secret-name"

	// ClustermeshApiserverRemoteCertGenerate can be set to true to generate
	// and store a new ClustermeshApiserver remote secret. If true then any
	// existing secret is overwritten with a new one.
	ClustermeshApiserverRemoteCertGenerate = "clustermesh-apiserver-remote-cert-generate"
	// ClustermeshApiserverRemoteCertCommonName is the Clustermesh API remote
	// x509 certificate CN value.
	ClustermeshApiserverRemoteCertCommonName = "clustermesh-apiserver-remote-cert-common-name"
	// ClustermeshApiserverRemoteCertValidityDuration represent how much time
	// Clustermesh API remote certificate generated by certgen is valid.
	ClustermeshApiserverRemoteCertValidityDuration = "clustermesh-apiserver-remote-cert-validity-duration"
	// ClustermeshApiserverRemoteCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API remote certificate is written to.
	ClustermeshApiserverRemoteCertSecretName = "clustermesh-apiserver-remote-cert-secret-name"
)

// CertGenConfig contains the main configuration options
type CertGenConfig struct {
	// Debug enables debug messages.
	Debug bool

	// ShipyardNamespace is the Kubernetes namespace in which Shipyard is
	// installed.
	ShipyardNamespace string

	// K8sKubeConfigPath is the path to the kubeconfig If empty, the in-cluster
	// configuration is used.
	K8sKubeConfigPath string
	// K8sRequestTimeout specifies the timeout for K8s API requests
	K8sRequestTimeout time.Duration

	// CACertFile is the path to the Shipyard CA cert PEM (if CAGenerate is
	// false).
	CACertFile string
	// CAKeyFile is the path to the Shipyard CA key PEM (if CAGenerate is false).
	CAKeyFile string

	// CAGenerate can be set to true to generate a new Shipyard CA secret.  If
	// CAReuseSecret is true, then a new CA secret only is created if existing
	// one is not found.
	CAGenerate bool
	// CAReuseSecret can be set to true to store and load the Shipyard CA from
	// the secret if it exists. Setting to false will delete the old Secret and
	// force regeneration.
	CAReuseSecret bool
	// CACommonName is the Shipyard CA x509 certificate CN value.
	CACommonName string
	// CAValidityDuration represent how much time the Shipyard CA certificate
	// generated by certgen is valid.
	CAValidityDuration time.Duration
	// CASecretName is the Kubernetes Secret in which the Shipyard CA certificate
	// is read from and/or written to.
	CASecretName string
	// CASecretNamespace is the Kubernetes Namespace in which the Shipyard CA
	// Secret will be stored.
	CASecretNamespace string

	// TriangleRelayClientCertGenerate can be set to true to generate and store a
	// Triangle Relay client TLS certificate (used for the mTLS handshake with
	// the Triangle servers).
	TriangleRelayClientCertGenerate bool
	// TriangleRelayClientCertCommonName is the Triangle Relay client x509
	// certificate CN value.
	TriangleRelayClientCertCommonName string
	// TriangleRelayClientCertValidityDuration represent how much time the Triangle
	// Relay client certificate generated by certgen is valid.
	TriangleRelayClientCertValidityDuration time.Duration
	// TriangleRelayClientCertSecretName is the Kubernetes Secret in which the
	// Triangle Relay client certificate is written to.
	TriangleRelayClientCertSecretName string
	// TriangleRelayClientCertSecretNamespace is the Kubernetes Namespace in
	// which the Triangle Relay client certificate Secret will be stored.
	TriangleRelayClientCertSecretNamespace string

	// TriangleRelayServerCertGenerate can be set to true to generate and store a
	// Triangle Relay server TLS certificate.
	TriangleRelayServerCertGenerate bool
	// TriangleRelayServerCertCommonName is the Triangle Relay server x509
	// certificate CN value (also used as DNS SAN).
	TriangleRelayServerCertCommonName string
	// TriangleRelayServerCertValidityDuration represent how much time the Triangle
	// Relay server certificate generated by certgen is valid.
	TriangleRelayServerCertValidityDuration time.Duration
	// TriangleRelayServerCertSecretName is the Kubernetes Secret in which the
	// Triangle Relay server certificate is written to.
	TriangleRelayServerCertSecretName string
	// TriangleRelayServerCertSecretNamespace where the Triangle Relay server cert
	// and key will be stored.
	TriangleRelayServerCertSecretNamespace string

	// TriangleServerCertGenerate can be set to true to generate and store a
	// Triangle server TLS certificate.
	TriangleServerCertGenerate bool
	// TriangleServerCertCommonName is the Triangle server x509 certificate CN
	// value (also used as DNS SAN).
	TriangleServerCertCommonName string
	// TriangleServerCertValidityDuration represent how much time the Triangle
	// server certificate generated by certgen is valid.
	TriangleServerCertValidityDuration time.Duration
	// TriangleServerCertSecretName is the Kubernetes Secret in which the Triangle
	// server certificate is written to.
	TriangleServerCertSecretName string
	// TriangleServerCertSecretNamespace is the Kubernetes Namespace in which the
	// Triangle server certificate Secret will be stored.
	TriangleServerCertSecretNamespace string

	// ClustermeshApiserverServerCertGenerate can be set to true to generate
	// and store a new Clustermesh API server TLS certificate.
	ClustermeshApiserverServerCertGenerate bool
	// ClustermeshApiserverServerCertCommonName is the Clustermesh API server
	// x509 certificate CN value (also used as DNS SAN).
	ClustermeshApiserverServerCertCommonName string
	// ClustermeshApiserverServerCertValidityDuration represent how much time
	// Clustermesh API server certificate generated by certgen is valid.
	ClustermeshApiserverServerCertValidityDuration time.Duration
	// ClustermeshApiserverServerCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API server certificate is written to.
	ClustermeshApiserverServerCertSecretName string
	// ClustermeshApiserverServerCertSANs is the list of SANs to add to the
	// Clustermesh API server certificate.
	ClustermeshApiserverServerCertSANs []string

	// ClustermeshApiserverAdminCertGenerate can be set to true to generate and
	// store a new Clustermesh API admin TLS certificate.
	ClustermeshApiserverAdminCertGenerate bool
	// ClustermeshApiserverAdminCertCommonName is the Clustermesh API admin
	// x509 certificate CN value.
	ClustermeshApiserverAdminCertCommonName string
	// ClustermeshApiserverAdminCertValidityDuration represent how much time
	// Clustermesh API admin certificate generated by certgen is valid.
	ClustermeshApiserverAdminCertValidityDuration time.Duration
	// ClustermeshApiserverAdminCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API admin certificate is written to.
	ClustermeshApiserverAdminCertSecretName string

	// ClustermeshApiserverClientCertGenerate can be set to true to generate and
	// store a new Clustermesh API client TLS certificate.
	ClustermeshApiserverClientCertGenerate bool
	// ClustermeshApiserverClientCertCommonName is the Clustermesh API client
	// x509 certificate CN value.
	ClustermeshApiserverClientCertCommonName string
	// ClustermeshApiserverClientCertValidityDuration represent how much time
	// Clustermesh API client certificate generated by certgen is valid.
	ClustermeshApiserverClientCertValidityDuration time.Duration
	// ClustermeshApiserverClientCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API client certificate is written to.
	ClustermeshApiserverClientCertSecretName string

	// ClustermeshApiserverRemoteCertGenerate can be set to true to generate and
	// store a new Clustermesh API remote TLS certificate.
	ClustermeshApiserverRemoteCertGenerate bool
	// ClustermeshApiserverRemoteCertCommonName is the Clustermesh API remote
	// x509 certificate CN value.
	ClustermeshApiserverRemoteCertCommonName string
	// ClustermeshApiserverRemoteCertValidityDuration represent how much time
	// Clustermesh API remote certificate generated by certgen is valid.
	ClustermeshApiserverRemoteCertValidityDuration time.Duration
	// ClustermeshApiserverRemoteCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API remote certificate is written to.
	ClustermeshApiserverRemoteCertSecretName string
}

// getStringWithFallback returns the value associated with the key as a string
// if it is non-empty. If the value is empty, this function returns the value
// associated with fallbackKey
func getStringWithFallback(vp *viper.Viper, key, fallbackKey string) string { //nolint:unparam
	if value := vp.GetString(key); value != "" {
		return value
	}
	return vp.GetString(fallbackKey)
}

// PopulateFrom populates the config struct with the values provided by vp
func (c *CertGenConfig) PopulateFrom(vp *viper.Viper) {
	c.Debug = vp.GetBool(Debug)
	c.K8sKubeConfigPath = vp.GetString(K8sKubeConfigPath)
	c.K8sRequestTimeout = vp.GetDuration(K8sRequestTimeout)

	c.CACertFile = vp.GetString(CACertFile)
	c.CAKeyFile = vp.GetString(CAKeyFile)

	c.CAGenerate = vp.GetBool(CAGenerate)
	c.CAReuseSecret = vp.GetBool(CAReuseSecret)
	c.CACommonName = vp.GetString(CACommonName)
	c.CAValidityDuration = vp.GetDuration(CAValidityDuration)
	c.CASecretName = vp.GetString(CASecretName)
	c.CASecretNamespace = getStringWithFallback(vp, CASecretNamespace, ShipyardNamespace)

	c.TriangleRelayClientCertGenerate = vp.GetBool(TriangleRelayClientCertGenerate)
	c.TriangleRelayClientCertCommonName = vp.GetString(TriangleRelayClientCertCommonName)
	c.TriangleRelayClientCertValidityDuration = vp.GetDuration(TriangleRelayClientCertValidityDuration)
	c.TriangleRelayClientCertSecretName = vp.GetString(TriangleRelayClientCertSecretName)
	c.TriangleRelayClientCertSecretNamespace = getStringWithFallback(vp, TriangleRelayClientCertSecretNamespace, ShipyardNamespace)

	c.TriangleRelayServerCertGenerate = vp.GetBool(TriangleRelayServerCertGenerate)
	c.TriangleRelayServerCertCommonName = vp.GetString(TriangleRelayServerCertCommonName)
	c.TriangleRelayServerCertValidityDuration = vp.GetDuration(TriangleRelayServerCertValidityDuration)
	c.TriangleRelayServerCertSecretName = vp.GetString(TriangleRelayServerCertSecretName)
	c.TriangleRelayServerCertSecretNamespace = getStringWithFallback(vp, TriangleRelayServerCertSecretNamespace, ShipyardNamespace)

	c.TriangleServerCertGenerate = vp.GetBool(TriangleServerCertGenerate)
	c.TriangleServerCertCommonName = vp.GetString(TriangleServerCertCommonName)
	c.TriangleServerCertValidityDuration = vp.GetDuration(TriangleServerCertValidityDuration)
	c.TriangleServerCertSecretName = vp.GetString(TriangleServerCertSecretName)
	c.TriangleServerCertSecretNamespace = getStringWithFallback(vp, TriangleServerCertSecretNamespace, ShipyardNamespace)

	c.ShipyardNamespace = vp.GetString(ShipyardNamespace)

	c.ClustermeshApiserverServerCertGenerate = vp.GetBool(ClustermeshApiserverServerCertGenerate)
	c.ClustermeshApiserverServerCertCommonName = vp.GetString(ClustermeshApiserverServerCertCommonName)
	c.ClustermeshApiserverServerCertValidityDuration = vp.GetDuration(ClustermeshApiserverServerCertValidityDuration)
	c.ClustermeshApiserverServerCertSecretName = vp.GetString(ClustermeshApiserverServerCertSecretName)
	c.ClustermeshApiserverServerCertSANs = vp.GetStringSlice(ClustermeshApiserverServerCertSANs)

	c.ClustermeshApiserverAdminCertGenerate = vp.GetBool(ClustermeshApiserverAdminCertGenerate)
	c.ClustermeshApiserverAdminCertCommonName = vp.GetString(ClustermeshApiserverAdminCertCommonName)
	c.ClustermeshApiserverAdminCertValidityDuration = vp.GetDuration(ClustermeshApiserverAdminCertValidityDuration)
	c.ClustermeshApiserverAdminCertSecretName = vp.GetString(ClustermeshApiserverAdminCertSecretName)

	c.ClustermeshApiserverClientCertGenerate = vp.GetBool(ClustermeshApiserverClientCertGenerate)
	c.ClustermeshApiserverClientCertCommonName = vp.GetString(ClustermeshApiserverClientCertCommonName)
	c.ClustermeshApiserverClientCertValidityDuration = vp.GetDuration(ClustermeshApiserverClientCertValidityDuration)
	c.ClustermeshApiserverClientCertSecretName = vp.GetString(ClustermeshApiserverClientCertSecretName)

	c.ClustermeshApiserverRemoteCertGenerate = vp.GetBool(ClustermeshApiserverRemoteCertGenerate)
	c.ClustermeshApiserverRemoteCertCommonName = vp.GetString(ClustermeshApiserverRemoteCertCommonName)
	c.ClustermeshApiserverRemoteCertValidityDuration = vp.GetDuration(ClustermeshApiserverRemoteCertValidityDuration)
	c.ClustermeshApiserverRemoteCertSecretName = vp.GetString(ClustermeshApiserverRemoteCertSecretName)
}