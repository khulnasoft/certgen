// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Khulnasoft

package defaults

import "time"

const (
	// Debug enables debug messages.
	Debug = false

	// ShipyardNamespace is the Kubernetes namespace in which Shipyard is
	// installed.
	ShipyardNamespace = "kube-system"

	// K8sRequestTimeout specifies the timeout for K8s API requests.
	K8sRequestTimeout = 60 * time.Second

	// CAGenerate can be set to true to generate a new Shipyard CA secret.
	// If CAReuseSecret is true, then a new CA secret only is created if
	// existing one is not found.
	CAGenerate = false
	// CAReuseSecret can be set to true to store and load the Shipyard CA from
	// the secret if it exists. Setting to false will delete the old Secret and
	// force regeneration.
	CAReuseSecret = false
	// CACommonName is the Shipyard CA x509 certificate CN value.
	CACommonName = "Shipyard CA"
	// CAValidityDuration represent how much time the Shipyard CA certificate
	// generated by certgen is valid.
	CAValidityDuration = 3 * 365 * 24 * time.Hour
	// CASecretName is the Kubernetes Secret in which the Shipyard CA certificate
	// is read from and/or written to.
	CASecretName = "shipyard-ca"

	// TriangleServerCertGenerate can be set to true to generate and store a
	// Triangle server TLS certificate.
	TriangleServerCertGenerate = false
	// TriangleServerCertCommonName is the Triangle server x509 certificate CN
	// value (also used as DNS SAN).
	TriangleServerCertCommonName = "*.default.triangle-grpc.khulnasoft.com"
	// TriangleServerCertValidityDuration represent how much time the Triangle
	// server certificate generated by certgen is valid.
	TriangleServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	// TriangleServerCertSecretName is the Kubernetes Secret in which the Triangle
	// server certificate is written to.
	TriangleServerCertSecretName = "triangle-server-certs" //#nosec

	// TriangleRelayServerCertGenerate can be set to true to generate and store a
	// Triangle Relay server TLS certificate.
	TriangleRelayServerCertGenerate = false
	// TriangleRelayServerCertCommonName is the Triangle Relay server x509
	// certificate CN value (also used as DNS SAN).
	TriangleRelayServerCertCommonName = "*.triangle-relay.khulnasoft.com"
	// TriangleRelayServerCertValidityDuration represent how much time the Triangle
	// Relay server certificate generated by certgen is valid.
	TriangleRelayServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	// TriangleRelayServerCertSecretName is the Kubernetes Secret in which the
	// Triangle Relay server certificate is written to.
	TriangleRelayServerCertSecretName = "triangle-relay-server-certs" //#nosec

	// TriangleRelayClientCertGenerate can be set to true to generate and store a
	// Triangle Relay client TLS certificate (used for the mTLS handshake with
	// the Triangle servers).
	TriangleRelayClientCertGenerate = false
	// TriangleRelayClientCertCommonName is the Triangle Relay client x509
	// certificate CN value.
	TriangleRelayClientCertCommonName = "*.triangle-relay.khulnasoft.com"
	// TriangleRelayClientCertValidityDuration represent how much time the Triangle
	// Relay client certificate generated by certgen is valid.
	TriangleRelayClientCertValidityDuration = 3 * 365 * 24 * time.Hour
	// TriangleRelayClientCertSecretName is the Kubernetes Secret in which the
	// Triangle Relay client certificate is written to.
	TriangleRelayClientCertSecretName = "triangle-relay-client-certs" //#nosec

	// ClustermeshApiserverServerCertGenerate can be set to true to generate
	// and store a new Clustermesh API server TLS certificate.
	ClustermeshApiserverServerCertGenerate = false
	// ClustermeshApiserverServerCertCommonName is the Clustermesh API server
	// x509 certificate CN value (also used as DNS SAN).
	ClustermeshApiserverServerCertCommonName = "clustermesh-apiserver.khulnasoft.com"
	// ClustermeshApiserverServerCertValidityDuration represent how much time
	// Clustermesh API server certificate generated by certgen is valid.
	ClustermeshApiserverServerCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverServerCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API server certificate is written to.
	ClustermeshApiserverServerCertSecretName = "clustermesh-apiserver-server-cert"

	// ClustermeshApiserverAdminCertGenerate can be set to true to generate and
	// store a new Clustermesh API admin TLS certificate.
	ClustermeshApiserverAdminCertGenerate = false
	// ClustermeshApiserverAdminCertCommonName is the Clustermesh API admin
	// x509 certificate CN value.
	ClustermeshApiserverAdminCertCommonName = "root"
	// ClustermeshApiserverAdminCertValidityDuration represent how much time
	// Clustermesh API admin certificate generated by certgen is valid.
	ClustermeshApiserverAdminCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverAdminCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API admin certificate is written to.
	ClustermeshApiserverAdminCertSecretName = "clustermesh-apiserver-admin-cert"

	// ClustermeshApiserverClientCertGenerate can be set to true to generate and
	// store a new Clustermesh API client TLS certificate.
	ClustermeshApiserverClientCertGenerate = false
	// ClustermeshApiserverClientCertCommonName is the Clustermesh API client
	// x509 certificate CN value.
	ClustermeshApiserverClientCertCommonName = "externalworkload"
	// ClustermeshApiserverClientCertValidityDuration represent how much time
	// Clustermesh API client certificate generated by certgen is valid.
	ClustermeshApiserverClientCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverClientCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API client certificate is written to.
	ClustermeshApiserverClientCertSecretName = "clustermesh-apiserver-client-cert"

	// ClustermeshApiserverRemoteCertGenerate can be set to true to generate and
	// store a new Clustermesh API remote TLS certificate.
	ClustermeshApiserverRemoteCertGenerate = false
	// ClustermeshApiserverRemoteCertCommonName is the Clustermesh API remote
	// x509 certificate CN value.
	ClustermeshApiserverRemoteCertCommonName = "remote"
	// ClustermeshApiserverRemoteCertValidityDuration represent how much time
	// Clustermesh API remote certificate generated by certgen is valid.
	ClustermeshApiserverRemoteCertValidityDuration = 3 * 365 * 24 * time.Hour
	// ClustermeshApiserverRemoteCertSecretName is the Kubernetes Secret in
	// which the Clustermesh API remote certificate is written to.
	ClustermeshApiserverRemoteCertSecretName = "clustermesh-apiserver-remote-cert"
)

var (
	// TriangleServerCertUsage are the key usages for the Triangle server x509
	// certificate.
	TriangleServerCertUsage = []string{"signing", "key encipherment", "server auth"}
	// TriangleRelayServerCertUsage are the key usages for the Triangle Relay
	// server x509 certificate.
	TriangleRelayServerCertUsage = []string{"signing", "key encipherment", "server auth"}
	// TriangleRelayClientCertUsage are the key usages for the Triangle Relay
	// client x509 certificate.
	TriangleRelayClientCertUsage = []string{"signing", "key encipherment", "server auth", "client auth"}
	// ClustermeshApiserverCertUsage are the key usages for the Clustermesh API
	// server x509 certificate.
	ClustermeshApiserverCertUsage = []string{"signing", "key encipherment", "server auth", "client auth"}
	// ClustermeshApiserverServerCertSANs is the list of SANs to add to the
	// Clustermesh API server certificate.
	ClustermeshApiserverServerCertSANs = []string{"*.mesh.khulnasoft.com"}
)