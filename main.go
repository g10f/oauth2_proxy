package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/mreiferson/go-options"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	flagSet := flag.NewFlagSet("oauth2_proxy", flag.ExitOnError)

	upstreams := StringArray{}
	skipAuthRegex := StringArray{}
	roles := StringArray{}

	config := flagSet.String("config", "oauth2_proxy.cfg", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.String("tls-cert", "", "path to certificate file")
	flagSet.String("tls-key", "", "path to private key file")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	flagSet.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint or file:// paths for static files. Routing is based on the path")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Var(&skipAuthRegex, "skip-auth-regex", "bypass authentication for requests path's that match (may be given multiple times)")

	flagSet.Var(&roles, "roles", "restrict logins to members of this google group (may be given multiple times).")
	flagSet.String("client-id", "", "the OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
	flagSet.String("custom-templates-dir", "", "path to custom html templates")
	flagSet.String("proxy-prefix", "/oauth2", "the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in)")

	flagSet.String("cookie-name", "_oauth2_proxy", "the name of the cookie that the oauth_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies")
	flagSet.String("cookie-domain", "", "an optional cookie domain to force cookies to (ie: .yourcompany.com)*")
	flagSet.Duration("cookie-expire", time.Duration(168) * time.Hour, "expire timeframe for cookie")
	flagSet.Duration("cookie-refresh", time.Duration(0), "refresh the cookie after this duration; 0 to disable")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")

	flagSet.Bool("request-logging", true, "Log requests to stdout")

	flagSet.String("provider", "google", "OAuth provider")
	flagSet.String("login-url", "", "Authentication endpoint")
	flagSet.String("redeem-url", "", "Token redemption endpoint")
	flagSet.String("profile-url", "", "Profile access endpoint")
	flagSet.String("resource", "", "The resource that is protected (Azure AD only)")
	flagSet.String("validate-url", "", "Access token validation endpoint")
	flagSet.String("scope", "", "OAuth scope specification")
	flagSet.String("approval-prompt", "force", "OAuth approval_prompt")

	flagSet.String("signature-key", "", "GAP-Signature request signature key (algorithm:secretkey)")

	flagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2_proxy v%s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	opts := NewOptions()

	cfg := make(EnvOptions)
	if *config != "" {
		_, err := toml.DecodeFile(*config, &cfg)
		if err != nil {
			log.Fatalf("ERROR: failed to load config file %s - %s", *config, err)
		}
	}
	cfg.LoadEnvForStruct(opts)
	options.Resolve(opts, flagSet, cfg)

	err := opts.Validate()
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}

	oauthproxy := NewOAuthProxy(opts)

	s := &Server{
		Handler: LoggingHandler(os.Stdout, oauthproxy, opts.RequestLogging),
		Opts:    opts,
	}
	s.ListenAndServe()
}
