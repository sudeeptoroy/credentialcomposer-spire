package main

import (
	"context"
	"sync"

//	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	//"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config defines the configuration for the plugin.
type Config struct {
	MySPIFFEIDUserPrefixes []string `hcl:"my_spiffe_id_user_prefixes"`
}

// Plugin implements the CredentialComposer plugin
type Plugin struct {
	// UnimplementedCredentialComposerServer is embedded to satisfy gRPC
	credentialcomposerv1.UnimplementedCredentialComposerServer

	// UnimplementedConfigServer is embedded to satisfy gRPC
	configv1.UnimplementedConfigServer

	// Configuration should be set atomically
	configMtx sync.RWMutex
	config    *Config
}

// ComposeServerX509CA implements the CredentialComposer ComposeServerX509CA RPC. Composes the SPIRE Server X509 CA.
// The server will supply the default attributes it will apply to the CA. If the plugin returns an empty response or
// NOT_IMPLEMENTED, the server will apply the default attributes. Otherwise, the returned attributes are used.
// If a CA is produced that does not conform to the SPIFFE X509-SVID specification for signing certificates, it will be rejected.
func (p *Plugin) ComposeServerX509CA(ctx context.Context, req *credentialcomposerv1.ComposeServerX509CARequest) (*credentialcomposerv1.ComposeServerX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// ComposeServerX509SVID implements the CredentialComposer ComposeServerX509SVID RPC. Composes the SPIRE Server X509-SVID.
// The server will supply the default attributes it will apply to the server X509-SVID. If the plugin returns an empty
// response or NOT_IMPLEMENTED, the server will apply the default attributes. Otherwise, the returned attributes are
// used. If an X509-SVID is produced that does not conform to the SPIFFE X509-SVID specification for leaf certificates,
// it will be rejected. This function cannot be used to modify the SPIFFE ID of the X509-SVID.
func (p *Plugin) ComposeServerX509SVID(ctx context.Context, req *credentialcomposerv1.ComposeServerX509SVIDRequest) (*credentialcomposerv1.ComposeServerX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// ComposeAgentX509SVID implements the CredentialComposer ComposeAgentX509SVID RPC. Composes the SPIRE Agent X509-SVID.
// The server will supply the default attributes it will apply to the agent X509-SVID. If the plugin returns an empty
// response or NOT_IMPLEMENTED, the server will apply the default attributes. Otherwise, the returned attributes are used.
// If an X509-SVID is produced that does not conform to the SPIFFE X509-SVID specification for leaf certificates, it will
// be rejected. This function cannot be used to modify the SPIFFE ID of the X509-SVID.
func (p *Plugin) ComposeAgentX509SVID(ctx context.Context, req *credentialcomposerv1.ComposeAgentX509SVIDRequest) (*credentialcomposerv1.ComposeAgentX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// ComposeWorkloadX509SVID implements the CredentialComposer ComposeWorkloadX509SVID RPC. Composes workload X509-SVIDs.
// The server will supply the default attributes it will apply to the workload X509-SVID. If the plugin returns an empty
// response or NOT_IMPLEMENTED, the server will apply the default attributes. Otherwise, the returned attributes are used.
// If an X509-SVID is produced that does not conform to the SPIFFE X509-SVID specification for leaf certificates, it will
// be rejected. This function cannot be used to modify the SPIFFE ID of the X509-SVID.
func (p *Plugin) ComposeWorkloadX509SVID(ctx context.Context, req *credentialcomposerv1.ComposeWorkloadX509SVIDRequest) (*credentialcomposerv1.ComposeWorkloadX509SVIDResponse, error) {
	// we may not need to configure this plugin.
	/*
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}
	*/

	/*
	// Extract SPIFFE ID Path from request
	spiffeIDRaw := req.GetSpiffeId()
	spiffeID, err := spiffeid.FromString(spiffeIDRaw)
	if err != nil {
		return nil, err
	}
	//path := spiffeID.Path()

	*/
/*

	// to start you may just have a simple db that 1 to 1 maps IAM roles <-> SPIFFE IDs, and based on the roles you pick specific attributes to populate the certificates with
	// it could simply just be a harcoded list here for demo

	// these are 4 examples of how to compose the certificates based on what we need

	principalNameOID := "1.3.6.1.4.1.311.20.2.3" // is is microsoft's OID for UPNs.
	principalNameValue := "bob@woodgrove.com"    // This should be extracted or composed dynamically based on your requirements

	resp := &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
		Attributes: &credentialcomposerv1.X509SVIDAttributes{
			Subject: &credentialcomposerv1.DistinguishedName{
				// Populate other fields as necessary
			},
			ExtraExtensions: []credentialcomposerv1.AttributeTypeAndValue{
				{
					Oid:      principalNameOID,
					Value:    []byte(principalNameValue), // Value should be encoded as required by the specification
					Critical: false,
				},
			},
		},
	}

*/
	// this is probably the easiest to use.
	rfc822NameValue := "<id>.onmicrosoft.com"

	/*
	resp2 := &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
		Attributes: &credentialcomposerv1.X509SVIDAttributes{
			DnsSans: []string{rfc822NameValue},
		},
	}
	*/
	
	req.Attributes.DnsSans = []string{rfc822NameValue}
	resp2 := &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
		Attributes: req.Attributes,
	}
	/* 
	req.Attributes.Attributes.ExtraExtensions.Id[]
		return &credentialcomposerv1.ComposeWorkloadJWTSVIDResponse{
					Attributes: req.Attributes,
						}, nil
						*/
/*
	skiOID := "2.5.29.14"
	skiValue := "123456789abcdef" // This value would typically be a hash of the public key
	resp3 := &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
		Attributes: &credentialcomposerv1.X509SVIDAttributes{
			ExtraExtensions: []credentialcomposerv1.X509Extension{
				{
					Oid:      skiOID,
					Value:    []byte(skiValue), // The actual SKI value
					Critical: false,
				},
			},
		},
	}

	sha1PublicKeyOID := "1.3.6.1.4.1.99999.2.1.1"
	sha1PublicKeyValue := "123456789abcdef" // The SHA-1 hash of the public key
	resp4 := &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
		Attributes: &credentialcomposerv1.X509SVIDAttributes{
			ExtraExtensions: []credentialcomposerv1.X509Extension{
				{
					Oid:      sha1PublicKeyOID,
					Value:    []byte(sha1PublicKeyValue), // The actual SHA-1 public key value
					Critical: false,
				},
			},
		},
	}
*/
	// we only need to use one method.  Pick the one that works best for you
	return resp2, nil
}

// ComposeWorkloadJWTSVID implements the CredentialComposer ComposeWorkloadJWTSVID RPC. Composes workload JWT-SVIDs.
// The server will supply the default attributes it will apply to the workload JWT-SVID. If the plugin returns an empty
// response or NOT_IMPLEMENTED, the server will apply the default attributes. Otherwise, the returned attributes are used.
// If a JWT-SVID is produced that does not conform to the SPIFFE JWT-SVID specification, it will be rejected.
// This function cannot be used to modify the SPIFFE ID of the JWT-SVID.
func (p *Plugin) ComposeWorkloadJWTSVID(ctx context.Context, req *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest) (*credentialcomposerv1.ComposeWorkloadJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, it may be invoked to reconfigure the plugin.
// As such, it should replace the previous configuration atomically.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	p.config = config
	p.configMtx.Unlock()
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func main() {
	plugin := new(Plugin)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		credentialcomposerv1.CredentialComposerPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}

