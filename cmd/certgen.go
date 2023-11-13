// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Khulnasoft

package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/khulnasoft/certgen/internal/defaults"
	"github.com/khulnasoft/certgen/internal/generate"
	"github.com/khulnasoft/certgen/internal/logging"
	"github.com/khulnasoft/certgen/internal/logging/logfields"
	"github.com/khulnasoft/certgen/internal/option"
	"github.com/khulnasoft/certgen/internal/version"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const binaryName = "shipyard-certgen"

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

// New creates and returns a certgen command.
func New() (*cobra.Command, error) {
	vp := viper.New()
	rootCmd := &cobra.Command{
		Use:           binaryName + " [flags]",
		Short:         binaryName,
		Long:          binaryName + " bootstraps TLS certificates and stores them as K8s secrets",
		SilenceErrors: true,
		Version:       version.Version,
		Run: func(cmd *cobra.Command, args []string) {
			option.Config.PopulateFrom(vp)

			if option.Config.Debug {
				logging.DefaultLogger.SetLevel(logrus.DebugLevel)
			}

			log.Infof("%s %s", binaryName, version.Version)

			if err := generateCertificates(); err != nil {
				log.WithError(err).Fatal("failed to generate certificates")
			}
		},
	}
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")

	flags := rootCmd.Flags()
	flags.BoolP(option.Debug, "D", defaults.Debug, "Enable debug messages")

	flags.String(option.K8sKubeConfigPath, "", "Path to the K8s kubeconfig file. If absent, the in-cluster config is used.")
	flags.Duration(option.K8sRequestTimeout, defaults.K8sRequestTimeout, "Timeout for K8s API requests")

	flags.String(option.CACertFile, "", "Path to provided Shipyard CA certificate file (required if Shipyard CA is not generated)")
	flags.String(option.CAKeyFile, "", "Path to provided Shipyard CA key file (required if Shipyard CA is not generated)")

	flags.Bool(option.CAGenerate, defaults.CAGenerate, "Generate and store Shipyard CA certificate")
	flags.Bool(option.CAReuseSecret, defaults.CAReuseSecret, "Reuse the Shipyard CA secret if it exists, otherwise generate a new one")
	flags.String(option.CACommonName, defaults.CACommonName, "Shipyard CA common name")
	flags.Duration(option.CAValidityDuration, defaults.CAValidityDuration, "Shipyard CA validity duration")
	flags.String(option.CASecretName, defaults.CASecretName, "Name of the K8s Secret where the Shipyard CA cert and key are stored in")
	flags.String(option.CASecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Shipyard CA cert and key are stored in")

	flags.Bool(option.TriangleRelayClientCertGenerate, defaults.TriangleRelayClientCertGenerate, "Generate and store Triangle Relay client certificate")
	flags.String(option.TriangleRelayClientCertCommonName, defaults.TriangleRelayClientCertCommonName, "Triangle Relay client certificate common name")
	flags.Duration(option.TriangleRelayClientCertValidityDuration, defaults.TriangleRelayClientCertValidityDuration, "Triangle Relay client certificate validity duration")
	flags.String(option.TriangleRelayClientCertSecretName, defaults.TriangleRelayClientCertSecretName, "Name of the K8s Secret where the Triangle Relay client cert and key are stored in")
	flags.String(option.TriangleRelayClientCertSecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Triangle Relay client cert and key are stored in")

	flags.Bool(option.TriangleRelayServerCertGenerate, defaults.TriangleRelayServerCertGenerate, "Generate and store Triangle Relay server certificate")
	flags.String(option.TriangleRelayServerCertCommonName, defaults.TriangleRelayServerCertCommonName, "Triangle Relay server certificate common name")
	flags.Duration(option.TriangleRelayServerCertValidityDuration, defaults.TriangleRelayServerCertValidityDuration, "Triangle Relay server certificate validity duration")
	flags.String(option.TriangleRelayServerCertSecretName, defaults.TriangleRelayServerCertSecretName, "Name of the K8s Secret where the Triangle Relay server cert and key are stored in")
	flags.String(option.TriangleRelayServerCertSecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Triangle Relay server cert and key are stored in")

	flags.Bool(option.TriangleServerCertGenerate, defaults.TriangleServerCertGenerate, "Generate and store Triangle server certificate")
	flags.String(option.TriangleServerCertCommonName, defaults.TriangleServerCertCommonName, "Triangle server certificate common name")
	flags.Duration(option.TriangleServerCertValidityDuration, defaults.TriangleServerCertValidityDuration, "Triangle server certificate validity duration")
	flags.String(option.TriangleServerCertSecretName, defaults.TriangleServerCertSecretName, "Name of the K8s Secret where the Triangle server cert and key are stored in")
	flags.String(option.TriangleServerCertSecretNamespace, "", "Overwrites the namespace of the K8s Secret where the Triangle server cert and key are stored in")

	// Extenal Workload certs
	flags.String(option.ShipyardNamespace, defaults.ShipyardNamespace, "Namespace where the cert secrets and configmaps are stored in")

	flags.Bool(option.ClustermeshApiserverServerCertGenerate, defaults.ClustermeshApiserverServerCertGenerate, "Generate and store clustermesh-apiserver server certificate")
	flags.String(option.ClustermeshApiserverServerCertCommonName, defaults.ClustermeshApiserverServerCertCommonName, "clustermesh-apiserver server certificate common name")
	flags.Duration(option.ClustermeshApiserverServerCertValidityDuration, defaults.ClustermeshApiserverServerCertValidityDuration, "clustermesh-apiserver server certificate validity duration")
	flags.String(option.ClustermeshApiserverServerCertSecretName, defaults.ClustermeshApiserverServerCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver server cert and key are stored in")
	flags.StringSlice(option.ClustermeshApiserverServerCertSANs, defaults.ClustermeshApiserverServerCertSANs, "clustermesh-apiserver server certificate SANs")

	flags.Bool(option.ClustermeshApiserverAdminCertGenerate, defaults.ClustermeshApiserverAdminCertGenerate, "Generate and store clustermesh-apiserver admin certificate")
	flags.String(option.ClustermeshApiserverAdminCertCommonName, defaults.ClustermeshApiserverAdminCertCommonName, "clustermesh-apiserver admin certificate common name")
	flags.Duration(option.ClustermeshApiserverAdminCertValidityDuration, defaults.ClustermeshApiserverAdminCertValidityDuration, "clustermesh-apiserver admin certificate validity duration")
	flags.String(option.ClustermeshApiserverAdminCertSecretName, defaults.ClustermeshApiserverAdminCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver admin cert and key are stored in")

	flags.Bool(option.ClustermeshApiserverClientCertGenerate, defaults.ClustermeshApiserverClientCertGenerate, "Generate and store clustermesh-apiserver client certificate")
	flags.String(option.ClustermeshApiserverClientCertCommonName, defaults.ClustermeshApiserverClientCertCommonName, "clustermesh-apiserver client certificate common name")
	flags.Duration(option.ClustermeshApiserverClientCertValidityDuration, defaults.ClustermeshApiserverClientCertValidityDuration, "clustermesh-apiserver client certificate validity duration")
	flags.String(option.ClustermeshApiserverClientCertSecretName, defaults.ClustermeshApiserverClientCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver client cert and key are stored in")

	flags.Bool(option.ClustermeshApiserverRemoteCertGenerate, defaults.ClustermeshApiserverRemoteCertGenerate, "Generate and store clustermesh-apiserver remote certificate")
	flags.String(option.ClustermeshApiserverRemoteCertCommonName, defaults.ClustermeshApiserverRemoteCertCommonName, "clustermesh-apiserver remote certificate common name")
	flags.Duration(option.ClustermeshApiserverRemoteCertValidityDuration, defaults.ClustermeshApiserverRemoteCertValidityDuration, "clustermesh-apiserver remote certificate validity duration")
	flags.String(option.ClustermeshApiserverRemoteCertSecretName, defaults.ClustermeshApiserverRemoteCertSecretName, "Name of the K8s Secret where the clustermesh-apiserver remote cert and key are stored in")

	// Sets up viper to read in flags via SHIPYARD_CERTGEN_ env variables
	vp.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	vp.SetEnvPrefix(binaryName)
	vp.AutomaticEnv()

	if err := vp.BindPFlags(flags); err != nil {
		return nil, err
	}

	return rootCmd, nil
}

// Execute runs the root command. This is called by main.main().
func Execute() error {
	cmd, err := New()
	if err != nil {
		return err
	}
	return cmd.Execute()
}

// k8sConfig creates a new Kubernetes config either based on the provided
// kubeconfig file or alternatively the in-cluster configuration.
func k8sConfig(kubeconfig string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	if kubeconfig == "" {
		config, err = rest.InClusterConfig()
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

// generateCertificates runs the main code to generate and store certificate
func generateCertificates() error {
	k8sClient, err := k8sConfig(option.Config.K8sKubeConfigPath)
	if err != nil {
		return fmt.Errorf("failed initialize kubernetes client: %w", err)
	}

	// Store after all the requested certs have been successfully generated
	count := 0

	shipyardCA := generate.NewCA(option.Config.CASecretName, option.Config.CASecretNamespace)

	if option.Config.CAGenerate {
		err = shipyardCA.Generate(option.Config.CACommonName, option.Config.CAValidityDuration)
		if err != nil {
			return fmt.Errorf("failed to generate Shipyard CA: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()

		err = shipyardCA.StoreAsSecret(ctx, k8sClient, !option.Config.CAReuseSecret)
		if err != nil {
			if !k8sErrors.IsAlreadyExists(err) || !option.Config.CAReuseSecret {
				return fmt.Errorf("failed to create secret for Shipyard CA: %w", err)
			}
			// reset so that we can re-load later as CAReuseSecret is true
			shipyardCA.Reset()
		} else {
			count++
		}
	} else if option.Config.CACertFile != "" && option.Config.CAKeyFile != "" {
		log.Info("Loading Shipyard CA from file")
		err = shipyardCA.LoadFromFile(option.Config.CACertFile, option.Config.CAKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load Shipyard CA from file: %w", err)
		}
	}

	if shipyardCA.IsEmpty() && option.Config.CAReuseSecret {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		err = shipyardCA.LoadFromSecret(ctx, k8sClient)
		if err != nil {
			return fmt.Errorf("failed to load Shipyard CA from secret: %w", err)
		}
		log.Info("Loaded Shipyard CA Secret")
	}

	var triangleServerCert *generate.Cert
	if option.Config.TriangleServerCertGenerate {
		log.Info("Generating server certificates for Triangle")
		triangleServerCert = generate.NewCert(
			option.Config.TriangleServerCertCommonName,
			option.Config.TriangleServerCertValidityDuration,
			defaults.TriangleServerCertUsage,
			option.Config.TriangleServerCertSecretName,
			option.Config.TriangleServerCertSecretNamespace,
		)
		err := triangleServerCert.Generate(shipyardCA)
		if err != nil {
			return fmt.Errorf("failed to generate Triangle server cert: %w", err)
		}
	}

	var triangleRelayClientCert *generate.Cert
	if option.Config.TriangleRelayClientCertGenerate {
		log.Info("Generating client certificates for Triangle Relay")
		triangleRelayClientCert = generate.NewCert(
			option.Config.TriangleRelayClientCertCommonName,
			option.Config.TriangleRelayClientCertValidityDuration,
			defaults.TriangleRelayClientCertUsage,
			option.Config.TriangleRelayClientCertSecretName,
			option.Config.TriangleRelayClientCertSecretNamespace,
		)
		err := triangleRelayClientCert.Generate(shipyardCA)
		if err != nil {
			return fmt.Errorf("failed to generate Triangle Relay client cert: %w", err)
		}
	}

	var triangleRelayServerCert *generate.Cert
	if option.Config.TriangleRelayServerCertGenerate {
		log.Info("Generating server certificates for Triangle Relay")
		triangleRelayServerCert = generate.NewCert(
			option.Config.TriangleRelayServerCertCommonName,
			option.Config.TriangleRelayServerCertValidityDuration,
			defaults.TriangleRelayServerCertUsage,
			option.Config.TriangleRelayServerCertSecretName,
			option.Config.TriangleRelayServerCertSecretNamespace,
		)
		err := triangleRelayServerCert.Generate(shipyardCA)
		if err != nil {
			return fmt.Errorf("failed to generate Triangle Relay server cert: %w", err)
		}
	}

	var clustermeshApiserverServerCert *generate.Cert
	if option.Config.ClustermeshApiserverServerCertGenerate {
		log.Info("Generating server certificate for ClustermeshApiserver")
		clustermeshApiserverServerCert = generate.NewCert(
			option.Config.ClustermeshApiserverServerCertCommonName,
			option.Config.ClustermeshApiserverServerCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverServerCertSecretName,
			option.Config.ShipyardNamespace,
		).WithHosts(
			append([]string{
				option.Config.ClustermeshApiserverServerCertCommonName,
				"127.0.0.1",
			}, option.Config.ClustermeshApiserverServerCertSANs...),
		)
		err = clustermeshApiserverServerCert.Generate(shipyardCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver server cert: %w", err)
		}
	}

	var clustermeshApiserverAdminCert *generate.Cert
	if option.Config.ClustermeshApiserverAdminCertGenerate {
		log.Info("Generating admin certificate for ClustermeshApiserver")
		clustermeshApiserverAdminCert = generate.NewCert(
			option.Config.ClustermeshApiserverAdminCertCommonName,
			option.Config.ClustermeshApiserverAdminCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverAdminCertSecretName,
			option.Config.ShipyardNamespace,
		).WithHosts([]string{"localhost"})
		err = clustermeshApiserverAdminCert.Generate(shipyardCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver admin cert: %w", err)
		}
	}

	var clustermeshApiserverClientCert *generate.Cert
	if option.Config.ClustermeshApiserverClientCertGenerate {
		log.Info("Generating client certificate for ClustermeshApiserver")
		clustermeshApiserverClientCert = generate.NewCert(
			option.Config.ClustermeshApiserverClientCertCommonName,
			option.Config.ClustermeshApiserverClientCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverClientCertSecretName,
			option.Config.ShipyardNamespace,
		)
		err = clustermeshApiserverClientCert.Generate(shipyardCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver client cert: %w", err)
		}
	}

	var clustermeshApiserverRemoteCert *generate.Cert
	if option.Config.ClustermeshApiserverRemoteCertGenerate {
		log.Info("Generating remote certificate for ClustermeshApiserver")
		clustermeshApiserverRemoteCert = generate.NewCert(
			option.Config.ClustermeshApiserverRemoteCertCommonName,
			option.Config.ClustermeshApiserverRemoteCertValidityDuration,
			defaults.ClustermeshApiserverCertUsage,
			option.Config.ClustermeshApiserverRemoteCertSecretName,
			option.Config.ShipyardNamespace,
		)
		err = clustermeshApiserverRemoteCert.Generate(shipyardCA)
		if err != nil {
			return fmt.Errorf("failed to generate ClustermeshApiserver remote cert: %w", err)
		}
	}

	if option.Config.TriangleServerCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := triangleServerCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Triangle server cert: %w", err)
		}
		count++
	}

	if option.Config.TriangleRelayClientCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := triangleRelayClientCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Triangle Relay client cert: %w", err)
		}
		count++
	}

	if option.Config.TriangleRelayServerCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := triangleRelayServerCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for Triangle Relay server cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverServerCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverServerCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver server cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverAdminCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverAdminCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver admin cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverClientCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverClientCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver client cert: %w", err)
		}
		count++
	}

	if option.Config.ClustermeshApiserverRemoteCertGenerate {
		ctx, cancel := context.WithTimeout(context.Background(), option.Config.K8sRequestTimeout)
		defer cancel()
		if err := clustermeshApiserverRemoteCert.StoreAsSecret(ctx, k8sClient); err != nil {
			return fmt.Errorf("failed to create secret for ClustermeshApiserver remote cert: %w", err)
		}
		count++
	}

	log.Infof("Successfully generated all %d requested certificates.", count)

	return nil
}