package main

import (
	"bufio"
	"fmt"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SeverityLevel int

const (
	Low SeverityLevel = iota + 1
	Medium
	High
	Critical
)

type Finding struct {
	File       string
	Name       string
	Match      string
	LineNumber int
	Severity   SeverityLevel
}

var severityMap = map[string]SeverityLevel{
	"1password-service-account-token":    Critical,
	"age-secret-key":                     Critical,
	"mongodb-connection-string":          Critical,
	"paypal-access-token":                Critical,
	"paypal-braintree-access-token":      Critical,
	"private-rsa-key":                    Critical,
	"square-access-token":                Critical,
	"square-oauth-secret":                Critical,
	"stripe-api-key":                     Critical,
	"stripe-restricted-api-key":          Critical,
	"adafruit-api-key":                   High,
	"adobe-client-secret":                High,
	"airtable-api-key":                   High,
	"algolia-api-key":                    High,
	"alibaba-access-key-id":              High,
	"alibaba-secret-key":                 High,
	"asana-client-secret":                High,
	"atlassian-api-token":                High,
	"authress-service-client-access-key": High,
	"aws-access-token":                   High,
	"azure-ad-client-secret":             High,
	"beamer-api-token":                   High,
	"bitbucket-client-secret":            High,
	"bittrex-access-key":                 High,
	"bittrex-secret-key":                 High,
	"cisco-meraki-api-key":               High,
	"clojars-api-token":                  High,
	"cloudflare-api-key":                 High,
	"cloudflare-global-api-key":          High,
	"cloudflare-origin-ca-key":           High,
	"codecov-access-token":               High,
	"cohere-api-token":                   High,
	"coinbase-access-token":              High,
	"confluent-access-key":               High,
	"contentful-delivery-api-token":      High,
	"databricks-api-token":               High,
	"datadog-access-token":               High,
	"defined-networking-api-token":       High,
	"digitalocean-access-token":          High,
	"discord-api-token":                  High,
	"discord-bot-token":                  High,
	"discord-client-secret":              High,
	"doppler-api-token":                  High,
	"droneci-access-token":               High,
	"dropbox-access-token":               High,
	"duffel-api-token":                   High,
	"dynatrace-api-token":                High,
	"easypost-api-token":                 High,
	"etsy-access-token":                  High,
	"facebook-access-token":              High,
	"facebook-oauth":                     High,
	"facebook-secret":                    High,
	"fastly-api-token":                   High,
	"finicity-api-token":                 High,
	"finicity-client-secret":             High,
	"finnhub-access-token":               High,
	"flickr-access-token":                High,
	"flutterwave-encryption-key":         High,
	"flutterwave-public-key":             High,
	"flutterwave-secret-key":             High,
	"flyio-access-token":                 High,
	"frameio-api-token":                  High,
	"freemius-secret-key":                High,
	"freshbooks-access-token":            High,
	"github-app-token":                   High,
	"github-fine-grained-pat":            High,
	"github-oauth":                       High,
	"github-pat":                         High,
	"github-personal-access-token":       High,
	"github-refresh-token":               High,
	"gitlab-cicd-job-token":              High,
	"gitlab-personal-access-token":       High,
	"gitlab-runner-authentication-token": High,
	"gitter-access-token":                High,
	"gocardless-api-token":               High,
	"google-api-key":                     High,
	"google-cloud-platform-api-key":      High,
	"google-cloud-platform-oauth":        High,
	"grafana-api-key":                    High,
	"grafana-cloud-api-token":            High,
	"grafana-service-account-token":      High,
	"harness-api-key":                    High,
	"hashicorp-tf-api-token":             High,
	"hashicorp-tf-password":              High,
	"heroku-api-key":                     High,
	"hubspot-api-key":                    High,
	"huggingface-access-token":           High,
	"huggingface-organization-api-token": High,
	"infracost-api-token":                High,
	"intercom-api-key":                   High,
	"intra42-client-secret":              High,
	"jfrog-api-key":                      High,
	"jfrog-identity-token":               High,
	"kraken-access-token":                High,
	"kubernetes-secret-yaml":             High,
	"kucoin-access-token":                High,
	"launchdarkly-access-token":          High,
	"linear-api-key":                     High,
	"linear-client-secret":               High,
	"linkedin-client-secret":             High,
	"lob-api-key":                        High,
	"lob-pub-api-key":                    High,
	"mailgun-signing-key":                High,
	"mapbox-api-token":                   High,
	"mattermost-access-token":            High,
	"messagebird-api-key":                High,
	"microsoft-teams-webhook":            High,
	"netlify-access-token":               High,
	"new-relic-browser-api-token":        High,
	"new-relic-insert-key":               High,
	"new-relic-user-api-id":              High,
	"new-relic-user-api-key":             High,
	"npm-access-token":                   High,
	"nuget-config-password":              High,
	"nytimes-access-token":               High,
	"octopus-deploy-api-key":             High,
	"okta-access-token":                  High,
	"openai-api-key":                     High,
	"openshift-user-token":               High,
	"phillips-hue-access-token":          High,
	"plaid-api-token":                    High,
	"plaid-secret-key":                   High,
	"planetscale-api-token":              High,
	"planetscale-oauth-token":            High,
	"planetscale-password":               High,
	"postman-api-token":                  High,
	"prefect-api-token":                  High,
	"privateai-api-token":                High,
	"pulumi-api-token":                   High,
	"pypi-upload-token":                  High,
	"rapidapi-access-token":              High,
	"readme-api-token":                   High,
	"rubygems-api-token":                 High,
	"scalingo-api-token":                 High,
	"sendbird-access-token":              High,
	"sendgrid-api-token":                 High,
	"sendinblue-api-token":               High,
	"sentry-access-token":                High,
	"sentry-org-token":                   High,
	"sentry-user-token":                  High,
	"settlemint-access-token":            High,
	"shippo-api-token":                   High,
	"shopify-access-token":               High,
	"shopify-shared-secret":              High,
	"sidekiq-secret":                     High,
	"slack-app-token":                    High,
	"slack-bot-token":                    High,
	"slack-config-access-token":          High,
	"slack-config-refresh-token":         High,
	"slack-legacy-bot-token":             High,
	"slack-legacy-token":                 High,
	"slack-legacy-workspace-token":       High,
	"slack-token":                        High,
	"slack-user-token":                   High,
	"snyk-api-token":                     High,
	"sonar-api-token":                    High,
	"sourcegraph-access-token":           High,
	"squarespace-access-token":           High,
	"stripe-access-token":                High,
	"sumologic-access-id":                High,
	"sumologic-access-token":             High,
	"telegram-bot-api-token":             High,
	"travisci-access-token":              High,
	"twitch-api-token":                   High,
	"twilio-api-key":                     High,
	"twitter-access-secret":              High,
	"twitter-access-token":               High,
	"twitter-api-key":                    High,
	"twitter-api-secret":                 High,
	"twitter-bearer-token":               High,
	"twitter-oauth":                      High,
	"typeform-api-token":                 High,
	"vault-batch-token":                  High,
	"vault-service-token":                High,
	"yandex-access-token":                High,
	"yandex-api-key":                     High,
	"yandex-aws-access-token":            High,
	"zendesk-secret-key":                 High,
	"adobe-client-id":                    Medium,
	"asana-client-id":                    Medium,
	"bitbucket-client-id":                Medium,
	"curl-auth-header":                   Medium,
	"curl-auth-user":                     Medium,
	"discord-client-id":                  Medium,
	"jwt":                                Medium,
	"jwt-base64":                         Medium,
	"linkedin-client-id":                 Medium,
	"mailchimp-api-key":                  Medium,
	"mailgun-api-key":                    Medium,
	"microsoft-fabric-api-token":         Medium,
	"picatic-api-key":                    Medium,
	"plaid-client-id":                    Medium,
	"secret-key-keyword":                 Medium,
	"sendbird-access-id":                 Medium,
	"slack-webhook-url":                  Medium,
	"teams-webhook":                      Medium,
	"cloudinary":                         Low,
	"gradle-distribution-url":            Low,
	"gradle-url":                         Low,
	"password-in-url":                    Low,
	"password-keyword":                   Low,
	"sidekiq-sensitive-url":              Low,
}

func censor(s string) string {
	if len(s) <= 6 {
		return s
	}
	return strings.Repeat("*", len(s)-6) + s[len(s)-6:]
}

func getSeverity(findingType string) SeverityLevel {
	if sev, exists := severityMap[findingType]; exists {
		return sev
	}
	return Medium
}

func compileRegexPatterns(patterns map[string]string) map[string]*regexp.Regexp {
	compiled := make(map[string]*regexp.Regexp)
	for name, pat := range patterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Regex derlenirken hata (%s): %v\n", name, err)
			os.Exit(1)
		}
		compiled[name] = re
	}
	return compiled
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	frequency := make(map[rune]float64)
	for _, r := range s {
		frequency[r]++
	}
	entropy := 0.0
	for _, count := range frequency {
		p := count / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func getRiskLevel(score int) string {
	if score >= 90 {
		return "Safe"
	} else if score >= 70 {
		return "Low Risk"
	} else if score >= 50 {
		return "Medium Risk"
	} else if score >= 30 {
		return "High Risk"
	} else {
		return "Critical Risk"
	}
}

var regexPatterns = map[string]string{
	"Cloudinary":                          `cloudinary://.*`,
	"Firebase URL":                        `.*firebaseio\.com`,
	"Slack Token":                         `(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`,
	"RSA private key":                     `-----BEGIN RSA PRIVATE KEY-----`,
	"SSH (DSA) private key":               `-----BEGIN DSA PRIVATE KEY-----`,
	"SSH (EC) private key":                `-----BEGIN EC PRIVATE KEY-----`,
	"PGP private key block":               `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"Amazon AWS Access Key ID":            `AKIA[0-9A-Z]{16}`,
	"Amazon MWS Auth Token":               `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	"Facebook Access Token":               `EAACEdEose0cBA[0-9A-Za-z]+`,
	"Facebook OAuth":                      `[fF][aA][cC][eE][bB][oO][oO][kK].*[\'\"]{0,1}[0-9a-f]{32}[\'\"]{0,1}`,
	"GitHub":                              `[gG][iI][tT][hH][uU][bB].*[\'\"]{0,1}[0-9a-zA-Z]{35,40}[\'\"]{0,1}`,
	"Generic Secret":                      `[sS][eE][cC][rR][eE][tT].*[\'\"]{0,1}[0-9a-zA-Z]{32,45}[\'\"]{0,1}`,
	"Google Cloud Platform API Key":       `AIza[0-9A-Za-z\-_]{35}`,
	"Google Cloud Platform OAuth":         `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
	"MailChimp API Key":                   `[0-9a-f]{32}-us[0-9]{1,2}`,
	"Mailgun API Key":                     `key-[0-9a-zA-Z]{32}`,
	"Password in URL":                     `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]`,
	"PayPal Braintree Access Token":       `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"Picatic API Key":                     `sk_live_[0-9a-z]{32}`,
	"Slack Webhook":                       `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
	"Teams Webhook":                       `https://[a-zA-Z0-9_.-]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9-]+/IncomingWebhook/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+`,
	"Stripe API Key":                      `sk_live_[0-9a-zA-Z]{24}`,
	"Stripe Restricted API Key":           `rk_live_[0-9a-zA-Z]{24}`,
	"Square Access Token":                 `sq0atp-[0-9A-Za-z\-_]{22}`,
	"Square OAuth Secret":                 `sq0csp-[0-9A-Za-z\-_]{43}`,
	"Twilio API Key":                      `SK[0-9a-fA-F]{32}`,
	"Twitter Access Token":                `[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
	"Twitter OAuth":                       `[tT][wW][iI][tT][tT][eE][rR].*[\'\"]{0,1}[0-9a-zA-Z]{35,44}[\'\"]{0,1}`,
	"Gradle Distribution URL":             `https?://services\.gradle\.org/distributions/gradle-[0-9]+\.[0-9]+(-[a-z]+)?\.zip`,
	"Gradle URL":                          `.*gradle\.org`,
	"GitHub Personal Access Token":        `ghp_[0-9a-zA-Z]{36}`,
	"GitLab Personal Access Token":        `glpat-[0-9a-zA-Z\-_]{20,}`,
	"Microsoft Fabric API Token":          `[0-9a-f]{64}`,
	"Slack Bot Token":                     `xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}`,
	"Discord Bot Token":                   `[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}`,
	"Firebase Service Account Key":        `["'][a-zA-Z0-9\-_]{20,}\@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com["']`,
	"PayPal Access Token":                 `A21AA[0-9A-Za-z\-_]{78}`,
	"Private RSA Key":                     `(?s)-----BEGIN PRIVATE KEY-----.*-----END PRIVATE KEY-----`,
	"MongoDB Connection String":           `mongodb\+srv://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@cluster[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]+/.*`,
	"Password Keyword":                    `(?i).*password.*`,
	"SECRET Key Keyword":                  `(?i).*secret.*`,
	"1password-service-account-token":     `ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`,
	"adafruit-api-key":                    `(?i)[\w.-]{0,50}?(?:adafruit)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"adobe-client-id":                     `(?i)[\w.-]{0,50}?(?:adobe)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"adobe-client-secret":                 `\b(p8e-(?i)[a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"age-secret-key":                      `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`,
	"airtable-api-key":                    `(?i)[\w.-]{0,50}?(?:airtable)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{17})(?:[\x60'"\s;]|\\[nr]|$)`,
	"algolia-api-key":                     `(?i)[\w.-]{0,50}?(?:algolia)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"alibaba-access-key-id":               `\b(LTAI(?i)[a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
	"alibaba-secret-key":                  `(?i)[\w.-]{0,50}?(?:alibaba)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$)`,
	"asana-client-id":                     `(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
	"asana-client-secret":                 `(?i)[\w.-]{0,50}?(?:asana)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"atlassian-api-token":                 `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:atlassian|confluence|jira)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)|\b(ATATT3[A-Za-z0-9_\-=]{186})(?:[\x60'"\s;]|\\[nr]|$)`,
	"authress-service-client-access-key":  `\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})(?:[\x60'"\s;]|\\[nr]|$)`,
	"aws-access-token":                    `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b`,
	"azure-ad-client-secret":              `(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])`,
	"beamer-api-token":                    `(?i)[\w.-]{0,50}?(?:beamer)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(b_[a-z0-9=_\-]{44})(?:[\x60'"\s;]|\\[nr]|$)`,
	"bitbucket-client-id":                 `(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"bitbucket-client-secret":             `(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"bittrex-access-key":                  `(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"bittrex-secret-key":                  `(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"cisco-meraki-api-key":                `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"clojars-api-token":                   `(?i)CLOJARS_[a-z0-9]{60}`,
	"cloudflare-api-key":                  `(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"cloudflare-global-api-key":           `(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{37})(?:[\x60'"\s;]|\\[nr]|$)`,
	"cloudflare-origin-ca-key":            `\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\x60'"\s;]|\\[nr]|$)`,
	"codecov-access-token":                `(?i)[\w.-]{0,50}?(?:codecov)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"cohere-api-token":                    `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"coinbase-access-token":               `(?i)[\w.-]{0,50}?(?:coinbase)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"confluent-access-token":              `(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
	"confluent-secret-key":                `(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"contentful-delivery-api-token":       `(?i)[\w.-]{0,50}?(?:contentful)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{43})(?:[\x60'"\s;]|\\[nr]|$)`,
	"curl-auth-header":                    `\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))"|'(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))')(?:\B|\s|\z)`,
	"curl-auth-user":                      `\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w${}@.-]+)))(?:\s|\z)`,
	"databricks-api-token":                `\b(dapi[a-f0-9]{32}(?:-\d)?)(?:[\x60'"\s;]|\\[nr]|$)`,
	"datadog-access-token":                `(?i)[\w.-]{0,50}?(?:datadog)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"defined-networking-api-token":        `(?i)[\w.-]{0,50}?(?:dnkey)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})(?:[\x60'"\s;]|\\[nr]|$)`,
	"digitalocean-access-token":           `\b(doo_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"digitalocean-pat":                    `\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"digitalocean-refresh-token":          `(?i)\b(dor_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"discord-api-token":                   `(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"discord-client-id":                   `(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{18})(?:[\x60'"\s;]|\\[nr]|$)`,
	"discord-client-secret":               `(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"doppler-api-token":                   `dp\.pt\.(?i)[a-z0-9]{43}`,
	"droneci-access-token":                `(?i)[\w.-]{0,50}?(?:droneci)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"dropbox-api-token":                   `(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{15})(?:[\x60'"\s;]|\\[nr]|$)`,
	"dropbox-long-lived-api-token":        `(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:[\x60'"\s;]|\\[nr]|$)`,
	"dropbox-short-lived-api-token":       `(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(sl\.[a-z0-9\-=_]{135})(?:[\x60'"\s;]|\\[nr]|$)`,
	"duffel-api-token":                    `duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`,
	"dynatrace-api-token":                 `dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`,
	"easypost-api-token":                  `\bEZAK(?i)[a-z0-9]{54}\b`,
	"easypost-test-api-token":             `\bEZTK(?i)[a-z0-9]{54}\b`,
	"etsy-access-token":                   `(?i)[\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)`,
	"facebook-access-token":               `(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"facebook-page-access-token":          `\b(EAA[MC](?i)[a-z0-9]{100,})(?:[\x60'"\s;]|\\[nr]|$)`,
	"facebook-secret":                     `(?i)[\w.-]{0,50}?(?:facebook)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"fastly-api-token":                    `(?i)[\w.-]{0,50}?(?:fastly)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"finicity-api-token":                  `(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"finicity-client-secret":              `(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
	"finnhub-access-token":                `(?i)[\w.-]{0,50}?(?:finnhub)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
	"flickr-access-token":                 `(?i)[\w.-]{0,50}?(?:flickr)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"flutterwave-encryption-key":          `FLWSECK_TEST-(?i)[a-h0-9]{12}`,
	"flutterwave-public-key":              `FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`,
	"flutterwave-secret-key":              `FLWSECK_TEST-(?i)[a-h0-9]{32}-X`,
	"flyio-access-token":                  `\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))(?:[\x60'"\s;]|\\[nr]|$)`,
	"frameio-api-token":                   `fio-u-(?i)[a-z0-9\-_=]{64}`,
	"freemius-secret-key":                 `(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']`,
	"freshbooks-access-token":             `(?i)[\w.-]{0,50}?(?:freshbooks)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"github-app-token":                    `(?:ghu|ghs)_[0-9a-zA-Z]{36}`,
	"github-fine-grained-pat":             `github_pat_\w{82}`,
	"github-oauth":                        `gho_[0-9a-zA-Z]{36}`,
	"github-pat":                          `ghp_[0-9a-zA-Z]{36}`,
	"github-refresh-token":                `ghr_[0-9a-zA-Z]{36}`,
	"gitlab-cicd-job-token":               `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`,
	"gitlab-deploy-token":                 `gldt-[0-9a-zA-Z_\-]{20}`,
	"gitlab-feature-flag-client-token":    `glffct-[0-9a-zA-Z_\-]{20}`,
	"gitlab-feed-token":                   `glft-[0-9a-zA-Z_\-]{20}`,
	"gitlab-incoming-mail-token":          `glimt-[0-9a-zA-Z_\-]{25}`,
	"gitlab-kubernetes-agent-token":       `glagent-[0-9a-zA-Z_\-]{50}`,
	"gitlab-oauth-app-secret":             `gloas-[0-9a-zA-Z_\-]{64}`,
	"gitlab-pat":                          `glpat-[\w-]{20}`,
	"gitlab-pat-routable":                 `\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`,
	"gitlab-ptt":                          `glptt-[0-9a-f]{40}`,
	"gitlab-rrt":                          `GR1348941[\w-]{20}`,
	"gitlab-runner-authentication-token":  `glrt-[0-9a-zA-Z_\-]{20}`,
	"gitlab-scim-token":                   `glsoat-[0-9a-zA-Z_\-]{20}`,
	"gitlab-session-cookie":               `_gitlab_session=[0-9a-z]{32}`,
	"gitter-access-token":                 `(?i)[\w.-]{0,50}?(?:gitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"gocardless-api-token":                `(?i)[\w.-]{0,50}?(?:gocardless)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(live_(?i)[a-z0-9\-_=]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"grafana-api-key":                     `(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`,
	"grafana-cloud-api-token":             `(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`,
	"grafana-service-account-token":       `(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`,
	"harness-api-key":                     `(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}`,
	"hashicorp-tf-api-token":              `(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`,
	"hashicorp-tf-password":               `(?i)[\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}("[a-z0-9=_\-]{8,20}")(?:[\x60'"\s;]|\\[nr]|$)`,
	"heroku-api-key":                      `(?i)[\w.-]{0,50}?(?:heroku)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"hubspot-api-key":                     `(?i)[\w.-]{0,50}?(?:hubspot)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"huggingface-access-token":            `\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`,
	"huggingface-organization-api-token":  `\b(api_org_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`,
	"infracost-api-token":                 `\b(ico-[a-zA-Z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"intercom-api-key":                    `(?i)[\w.-]{0,50}?(?:intercom)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{60})(?:[\x60'"\s;]|\\[nr]|$)`,
	"intra42-client-secret":               `\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"jfrog-api-key":                       `(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{73})(?:[\x60'"\s;]|\\[nr]|$)`,
	"jfrog-identity-token":                `(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"jwt":                                 `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)`,
	"jwt-base64":                          `\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0t2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emduUWlPaU)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}`,
	"kraken-access-token":                 `(?i)[\w.-]{0,50}?(?:kraken)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9\/=_\+\-]{80,90})(?:[\x60'"\s;]|\\[nr]|$)`,
	"kubernetes-secret-yaml":              `(?i)(?:\bkind:[ \t]*["']?\bsecret\b["']?(?:.|\s){0,200}?\bdata:(?:.|\s){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))|\bdata:(?:.|\s){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))(?:.|\s){0,200}?\bkind:[ \t]*["']?\bsecret\b["']?)`,
	"kucoin-access-token":                 `(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)`,
	"kucoin-secret-key":                   `(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"launchdarkly-access-token":           `(?i)[\w.-]{0,50}?(?:launchdarkly)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"linear-api-key":                      `lin_api_(?i)[a-z0-9]{40}`,
	"linear-client-secret":                `(?i)[\w.-]{0,50}?(?:linear)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"linkedin-client-id":                  `(?i)[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{14})(?:[\x60'"\s;]|\\[nr]|$)`,
	"linkedin-client-secret":              `(?i)[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
	"lob-api-key":                         `(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\x60'"\s;]|\\[nr]|$)`,
	"lob-pub-api-key":                     `(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\x60'"\s;]|\\[nr]|$)`,
	"mailchimp-api-key":                   `(?i)[\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32}-us\d\d)(?:[\x60'"\s;]|\\[nr]|$)`,
	"mailgun-private-api-token":           `(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(key-[a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"mailgun-pub-key":                     `(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"mailgun-signing-key":                 `(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`,
	"mapbox-api-token":                    `(?i)[\w.-]{0,50}?(?:mapbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:[\x60'"\s;]|\\[nr]|$)`,
	"mattermost-access-token":             `(?i)[\w.-]{0,50}?(?:mattermost)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{26})(?:[\x60'"\s;]|\\[nr]|$)`,
	"messagebird-api-token":               `(?i)[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{25})(?:[\x60'"\s;]|\\[nr]|$)`,
	"messagebird-client-id":               `(?i)[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"microsoft-teams-webhook":             `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`,
	"netlify-access-token":                `(?i)[\w.-]{0,50}?(?:netlify)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{40,46})(?:[\x60'"\s;]|\\[nr]|$)`,
	"new-relic-browser-api-token":         `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\x60'"\s;]|\\[nr]|$)`,
	"new-relic-insert-key":                `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"new-relic-user-api-id":               `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"new-relic-user-api-key":              `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\x60'"\s;]|\\[nr]|$)`,
	"npm-access-token":                    `(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`,
	"nuget-config-password":               `(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>`,
	"nytimes-access-token":                `(?i)[\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"octopus-deploy-api-key":              `\b(API-[A-Z0-9]{26})(?:[\x60'"\s;]|\\[nr]|$)`,
	"okta-access-token":                   `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(00[\w=\-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"openai-api-key":                      `\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
	"openshift-user-token":                `\b(sha256~[\w-]{43})(?:[^\w-]|\z)`,
	"plaid-api-token":                     `(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"plaid-client-id":                     `(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)`,
	"plaid-secret-key":                    `(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$)`,
	"planetscale-api-token":               `\b(pscale_tkn_(?i)[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"planetscale-oauth-token":             `\b(pscale_oauth_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"planetscale-password":                `(?i)\b(pscale_pw_(?i)[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"postman-api-token":                   `\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)`,
	"prefect-api-token":                   `\b(pnu_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`,
	"private-key":                         `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`,
	"privateai-api-token":                 `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:private[_-]?ai)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
	"pulumi-api-token":                    `\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"pypi-upload-token":                   `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`,
	"rapidapi-access-token":               `(?i)[\w.-]{0,50}?(?:rapidapi)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{50})(?:[\x60'"\s;]|\\[nr]|$)`,
	"readme-api-token":                    `\b(rdme_[a-z0-9]{70})(?:[\x60'"\s;]|\\[nr]|$)`,
	"rubygems-api-token":                  `\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nr]|$)`,
	"scalingo-api-token":                  `\b(tk-us-[\w-]{48})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sendbird-access-id":                  `(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sendbird-access-token":               `(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sendgrid-api-token":                  `\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sendinblue-api-token":                `\b(xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sentry-access-token":                 `(?i)[\w.-]{0,50}?(?:sentry)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sentry-org-token":                    `\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\z)`,
	"sentry-user-token":                   `\b(sntryu_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"settlemint-application-access-token": `\b(sm_aat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
	"settlemint-personal-access-token":    `\b(sm_pat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
	"settlemint-service-access-token":     `\b(sm_sat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
	"shippo-api-token":                    `\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"shopify-access-token":                `shpat_[a-fA-F0-9]{32}`,
	"shopify-custom-access-token":         `shpca_[a-fA-F0-9]{32}`,
	"shopify-private-app-access-token":    `shppa_[a-fA-F0-9]{32}`,
	"shopify-shared-secret":               `shpss_[a-fA-F0-9]{32}`,
	"sidekiq-secret":                      `(?i)[\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sidekiq-sensitive-url":               `(?i)\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`,
	"slack-app-token":                     `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`,
	"slack-bot-token":                     `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
	"slack-config-access-token":           `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}`,
	"slack-config-refresh-token":          `(?i)xoxe-\d-[A-Z0-9]{146}`,
	"slack-legacy-bot-token":              `xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}`,
	"slack-legacy-token":                  `xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`,
	"slack-legacy-workspace-token":        `xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}`,
	"slack-user-token":                    `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`,
	"slack-webhook-url":                   `(?:https?://)?hooks.slack.com/(?:services|workflows)/[A-Za-z0-9+/]{43,46}`,
	"snyk-api-token":                      `(?i)[\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sonar-api-token":                     `(?i)[\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sourcegraph-access-token":            `(?i)\b(\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\b)(?:[\x60'"\s;]|\\[nr]|$)`,
	"square-access-token":                 `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)`,
	"squarespace-access-token":            `(?i)[\w.-]{0,50}?(?:squarespace)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
	"stripe-access-token":                 `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)`,
	"sumologic-access-id":                 `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\x60'"\s;]|\\[nr]|$))`,
	"sumologic-access-token":              `(?i)[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
	"telegram-bot-api-token":              `(?i)[\w.-]{0,50}?(?:telegr)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34})(?:[\x60'"\s;]|\\[nr]|$)`,
	"travisci-access-token":               `(?i)[\w.-]{0,50}?(?:travis)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{22})(?:[\x60'"\s;]|\\[nr]|$)`,
	"twitch-api-token":                    `(?i)[\w.-]{0,50}?(?:twitch)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$)`,
	"twitter-access-secret":               `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{45})(?:[\x60'"\s;]|\\[nr]|$)`,
	"twitter-access-token":                `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\x60'"\s;]|\\[nr]|$)`,
	"twitter-api-key":                     `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{25})(?:[\x60'"\s;]|\\[nr]|$)`,
	"twitter-api-secret":                  `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{50})(?:[\x60'"\s;]|\\[nr]|$)`,
	"twitter-bearer-token":                `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\x60'"\s;]|\\[nr]|$)`,
	"typeform-api-token":                  `(?i)[\w.-]{0,50}?(?:typeform)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(tfp_[a-z0-9\-_\.=]{59})(?:[\x60'"\s;]|\\[nr]|$)`,
	"vault-batch-token":                   `\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)`,
	"vault-service-token":                 `\b((?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24})))(?:[\x60'"\s;]|\\[nr]|$)`,
	"yandex-access-token":                 `(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\x60'"\s;]|\\[nr]|$)`,
	"yandex-api-key":                      `(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:[\x60'"\s;]|\\[nr]|$)`,
	"yandex-aws-access-token":             `(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(YC[a-zA-Z0-9_\-]{38})(?:[\x60'"\s;]|\\[nr]|$)`,
	"zendesk-secret-key":                  `(?i)[\w.-]{0,50}?(?:zendesk)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
}

var compiledRegexPatterns = compileRegexPatterns(regexPatterns)

func scanDirectoryParallel(directory string) ([]Finding, int) {
	var findings []Finding
	var mu sync.Mutex
	excludedExtensions := []string{".ttf", ".png"}
	var filePaths []string

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Yol tarama hatası (%s): %v\n", path, err)
			return nil
		}
		if info.Mode().IsRegular() {
			ext := strings.ToLower(filepath.Ext(info.Name()))
			skip := false
			for _, ex := range excludedExtensions {
				if ext == ex {
					skip = true
					break
				}
			}
			if !skip {
				filePaths = append(filePaths, path)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dizin tarama hatası: %v\n", err)
		return findings, 0
	}

	scannedFiles := len(filePaths)

	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	fileCh := make(chan string)

	worker := func() {
		defer wg.Done()
		for filePath := range fileCh {
			res := processFileLineByLine(filePath)
			if len(res) > 0 {
				mu.Lock()
				findings = append(findings, res...)
				mu.Unlock()
			}
		}
	}

	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}
	for _, fp := range filePaths {
		fileCh <- fp
	}
	close(fileCh)
	wg.Wait()

	return findings, scannedFiles
}

func processFileLineByLine(filePath string) []Finding {
	var findings []Finding
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dosya okunurken hata (%s): %v\n", filePath, err)
		return findings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for name, re := range compiledRegexPatterns {
			matches := re.FindAllString(line, -1)
			if matches != nil {
				for _, match := range matches {
					if calculateEntropy(match) < 3.5 {
						continue
					}
					findings = append(findings, Finding{
						File:       filePath,
						Name:       name,
						Match:      match,
						LineNumber: lineNumber,
						Severity:   getSeverity(name),
					})
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Okuma hatası (%s): %v\n", filePath, err)
	}
	return findings
}

func logFindings(findings []Finding, directory string) string {
	dirName := filepath.Base(directory)
	if dirName == "." {
		dirName = "current_dir"
	}
	logFileName := fmt.Sprintf("scan_results_%s.log", dirName)
	f, err := os.Create(logFileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Log dosyası oluşturulurken hata: %v\n", err)
		return ""
	}
	defer f.Close()

	for _, finding := range findings {
		logEntry := fmt.Sprintf("Dosya: %s\nBulgu: %s\nEşleşme: %s\nSatır: %d",
			finding.File, finding.Name, finding.Match, finding.LineNumber)
		_, err := f.WriteString(logEntry + "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Log yazılırken hata (%s): %v\n", finding.File, err)
		}
	}
	fmt.Printf("Sonuçlar '%s' dosyasına kaydedildi.\n", logFileName)
	return logFileName
}

type FindingCategory struct {
	Name     string
	Severity SeverityLevel
	Count    int
}

type ReportData struct {
	ScanDate         string
	ScanTarget       string
	TotalFindings    int
	ScannedFileCount int
	SecurityScore    int
	RiskLevel        string
	Findings         []Finding
	Categories       []FindingCategory
	SeverityCounts   map[SeverityLevel]int
	LogoURL          string
	GenerationTime   string
}

func generateCategoryStats(findings []Finding) ([]FindingCategory, map[SeverityLevel]int) {
	categoryCounts := make(map[string]int)
	for _, finding := range findings {
		categoryCounts[finding.Name]++
	}
	var categories []FindingCategory
	for name, count := range categoryCounts {
		categories = append(categories, FindingCategory{
			Name:     name,
			Severity: getSeverity(name),
			Count:    count,
		})
	}
	sort.Slice(categories, func(i, j int) bool {
		if categories[i].Severity != categories[j].Severity {
			return categories[i].Severity > categories[j].Severity
		}
		return categories[i].Name < categories[j].Name
	})
	severityCounts := make(map[SeverityLevel]int)
	for _, category := range categories {
		severityCounts[category.Severity] += category.Count
	}
	return categories, severityCounts
}

func calculateSecurityScore(findings []Finding) int {
	if len(findings) == 0 {
		return 100
	}

	// Count findings by severity level
	severityCounts := make(map[SeverityLevel]int)
	for _, finding := range findings {
		sev := getSeverity(finding.Name)
		severityCounts[sev]++
	}

	// Define weights for each severity level
	weights := map[SeverityLevel]int{
		Low:      1,
		Medium:   3,
		High:     6,
		Critical: 10,
	}

	// Calculate weighted impact
	totalWeight := 0
	totalImpact := 0

	// Process each severity level
	for severity, count := range severityCounts {
		weight := weights[severity]
		totalWeight += weight * count
		totalImpact += weight * count * int(severity)
	}

	// Calculate base score
	baseScore := 100
	if totalWeight > 0 {
		// Use a more stable calculation method with proper scaling
		// Maximum possible severity is 4 (Critical)
		maximumPossibleImpact := float64(totalWeight * 4) // 4 is the maximum severity level
		impactPercentage := float64(totalImpact) / maximumPossibleImpact
		// Scale the impact to reduce the score proportionally
		baseScore = int(100.0 * (1.0 - impactPercentage))
	}

	// Ensure score stays within valid range
	if baseScore < 0 {
		baseScore = 0
	} else if baseScore > 100 {
		baseScore = 100
	}

	return baseScore
}

func parseLogFile(logFilePath string) ([]Finding, error) {
	file, err := os.Open(logFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var findings []Finding
	scanner := bufio.NewScanner(file)
	var currentFinding Finding
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "--------") {
			continue
		}
		if strings.HasPrefix(line, "Dosya: ") {
			if currentFinding.File != "" && currentFinding.Name != "" {
				findings = append(findings, currentFinding)
			}
			currentFinding = Finding{}
			currentFinding.File = strings.TrimPrefix(line, "Dosya: ")
		} else if strings.HasPrefix(line, "Bulgu: ") {
			currentFinding.Name = strings.TrimPrefix(line, "Bulgu: ")
			currentFinding.Severity = getSeverity(currentFinding.Name)
		} else if strings.HasPrefix(line, "Eşleşme: ") {
			currentFinding.Match = strings.TrimPrefix(line, "Eşleşme: ")
		} else if strings.HasPrefix(line, "Satır: ") {
			lineNumberStr := strings.TrimPrefix(line, "Satır: ")
			lineNumber, err := strconv.Atoi(lineNumberStr)
			if err == nil {
				currentFinding.LineNumber = lineNumber
			}
		}
	}
	if currentFinding.File != "" && currentFinding.Name != "" {
		findings = append(findings, currentFinding)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func GenerateHTMLReport(logFilePath string, scannedFileCount int) error {
	startTime := time.Now()
	findings, err := parseLogFile(logFilePath)
	if err != nil {
		return fmt.Errorf("log dosyası ayrıştırılırken hata: %v", err)
	}
	logFileName := filepath.Base(logFilePath)

	const realRegexPattern = "scan_results_(.+)\\.log"

	const censoredRegexDisplay = "*********(.+)\\.log"

	regex := regexp.MustCompile(realRegexPattern)

	fmt.Printf("Using regex pattern: %s\n", censoredRegexDisplay)

	matches := regex.FindStringSubmatch(logFileName)
	scanTarget := "Unknown"
	if len(matches) > 1 {
		scanTarget = matches[1]
	}
	categories, severityCounts := generateCategoryStats(findings)
	securityScore := calculateSecurityScore(findings)

	duration := time.Since(startTime)
	var generationTime string
	if duration < time.Second {
		generationTime = fmt.Sprintf("%.2f ms", float64(duration)/float64(time.Millisecond))
	} else {
		generationTime = fmt.Sprintf("%.2f s", float64(duration)/float64(time.Second))
	}

	reportData := ReportData{
		ScanDate:         time.Now().Format("2006-01-02 15:04:05"),
		ScanTarget:       scanTarget,
		TotalFindings:    len(findings),
		ScannedFileCount: scannedFileCount,
		SecurityScore:    securityScore,
		RiskLevel:        getRiskLevel(securityScore),
		Findings:         findings,
		Categories:       categories,
		SeverityCounts:   severityCounts,
		LogoURL:          "mascot.png",
		GenerationTime:   generationTime,
	}
	reportFileName := fmt.Sprintf("security_report_%s.html", scanTarget)
	reportFile, err := os.Create(reportFileName)
	if err != nil {
		return fmt.Errorf("rapor dosyası oluşturulurken hata: %v", err)
	}
	defer reportFile.Close()

	const reportTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report - {{.ScanDate}}</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --critical: #dc3545;
      --high: #fd7e14;
      --medium: #ffc107;
      --low: #20c997;
      --bg-primary: #f8f9fa;
      --bg-secondary: #ffffff;
      --text-primary: #212529;
      --text-secondary: #6c757d;
      --border-color: #dee2e6;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Inter', sans-serif; line-height: 1.6; color: var(--text-primary); background: var(--bg-primary); padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { 
      display: flex; justify-content: space-between; align-items: center;
      background: var(--bg-secondary); padding: 2rem; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem;
    }
    .header-left { flex: 1; }
    .header-right { flex-shrink: 0; }
    .logo { max-height: 80px; }
    .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .dashboard-card { background: var(--bg-secondary); padding: 1.5rem; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .score-card { text-align: center; padding: 2rem; }
    .score-number { font-size: 3rem; font-weight: 600; margin-bottom: 0.5rem; }
    .risk-label { display: inline-block; padding: 0.5rem 1rem; border-radius: 20px; font-weight: 500; margin-top: 1rem; }
    .risk-critical { background: var(--critical); color: white; }
    .risk-high { background: var(--high); color: white; }
    .risk-medium { background: var(--medium); color: var(--text-primary); }
    .risk-low { background: var(--low); color: white; }
    .controls-section { background: var(--bg-secondary); padding: 1rem; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem; }
    .filter-controls { display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; }
    .search-box, .filter-select { padding: 0.5rem; border: 1px solid var(--border-color); border-radius: 4px; font-family: inherit; }
    .selected-category-card, .selected-severity-card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 0.5rem 1rem;
      font-weight: 600;
      margin-left: 1rem;
    }
    .findings-section { margin-top: 2rem; }
    .findings-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
    .finding-card { background: var(--bg-secondary); border-radius: 10px; margin-bottom: 1rem; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .finding-header { padding: 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); }
    .severity-badge { padding: 0.25rem 0.75rem; border-radius: 15px; font-size: 0.875rem; font-weight: 500; }
    .severity-critical { background: var(--critical); color: white; }
    .severity-high { background: var(--high); color: white; }
    .severity-medium { background: var(--medium); color: var(--text-primary); }
    .severity-low { background: var(--low); color: white; }
    .finding-content { padding: 1rem; }
    .code-snippet { font-family: 'Monaco', monospace; background: #2b2b2b; color: #f8f8f2; padding: 1rem; border-radius: 6px; margin: 0.5rem 0; }
    .line-number { color: #999; margin-right: 1rem; user-select: none; }
    .file-path { color: var(--text-secondary); font-size: 0.875rem; margin-top: 0.5rem; }
    .chart-container { position: relative; height: 300px; }
    .no-results { text-align: center; padding: 2rem; color: var(--text-secondary); }
    .summary-card { text-align: center; }
    .summary-content { display: flex; flex-wrap: wrap; justify-content: space-around; margin-top: 1rem; }
    .summary-item { flex: 1; min-width: 120px; margin: 0.5rem; }
    .summary-label { display: block; font-weight: 600; margin-bottom: 0.5rem; }
    .summary-value { font-size: 1.5rem; font-weight: 700; }
    /* Footer styles */
    .footer {
      margin-top: 3rem;
      padding: 1.5rem;
      background: var(--bg-secondary);
      border-radius: 10px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      text-align: center;
      color: var(--text-secondary);
      font-size: 0.9rem;
    }
    .footer p {
      margin: 0.5rem 0;
    }
    .footer-divider {
      margin: 0.5rem auto;
      width: 50px;
      border-top: 2px solid var(--border-color);
    }
    @media (max-width: 768px) {
      body { padding: 1rem; }
      .dashboard-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-left">
        <h1>Sensitive Data Scan Report</h1>
        <p>Scan completed on {{.ScanDate}}</p>
        <p>Target: {{.ScanTarget}}</p>
        <p>Scanned Files: {{.ScannedFileCount}}</p>
        <p>Report generation time: {{.GenerationTime}}</p>
      </div>
<div class="header-right">
  <img src="{{.LogoURL}}" style="width: 150px; height: auto;" alt="Logo" class="logo">
</div>

    </div>
    <div class="dashboard-grid">
      <div class="dashboard-card score-card">
        <h2>Security Score</h2>
        <div class="score-number">{{.SecurityScore}}</div>
        <div class="risk-label risk-{{toLowerCase .RiskLevel}}">{{.RiskLevel}}</div>
      </div>
      <div class="dashboard-card">
        <h2>Severity Distribution</h2>
        <div class="chart-container">
          <canvas id="severityChart"></canvas>
        </div>
      </div>
      <div class="dashboard-card summary-card">
        <h2>Summary</h2>
        <div class="summary-content">
          <div class="summary-item">
            <span class="summary-label">Total Findings</span>
            <span class="summary-value">{{.TotalFindings}}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">Scanned Files</span>
            <span class="summary-value">{{.ScannedFileCount}}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">Critical</span>
            <span class="summary-value">{{index .SeverityCounts 4}}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">High</span>
            <span class="summary-value">{{index .SeverityCounts 3}}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">Medium</span>
            <span class="summary-value">{{index .SeverityCounts 2}}</span>
          </div>
          <div class="summary-item">
            <span class="summary-label">Low</span>
            <span class="summary-value">{{index .SeverityCounts 1}}</span>
          </div>
        </div>
      </div>
    </div>
    <div class="controls-section">
      <div class="filter-controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search findings...">
        <select id="severityFilter" class="filter-select">
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <div id="selectedSeverityCard" class="selected-severity-card" style="display:none;"></div>
        <select id="categoryFilter" class="filter-select">
          <option value="all">All Categories</option>
          {{range .Categories}}
            <option value="{{.Name | lower}}">{{.Name}}</option>
          {{end}}
        </select>
        <div id="selectedCategoryCard" class="selected-category-card" style="display:none;"></div>
      </div>
    </div>
    <div class="findings-section">
      <div class="findings-header">
        <h2>Detailed Findings</h2>
      </div>
      {{range .Findings}}
      <div class="finding-card" data-severity="{{getSeverityName .Severity | lower}}" data-category="{{.Name | lower}}">
        <div class="finding-header">
          <h3>{{.Name}}</h3>
          <span class="severity-badge severity-{{toLowerCase (getSeverityName .Severity)}}">
            {{getSeverityName .Severity}}
          </span>
        </div>
        <div class="finding-content">
          <div class="code-snippet">
            <span class="line-number">Line {{.LineNumber}}:</span>
            <span>{{censor .Match}}</span>
          </div>
          <p class="file-path">{{.File}}</p>
        </div>
      </div>
      {{end}}
      <div class="no-results" style="display:none;">No findings match your criteria.</div>
    </div>
  </div>
  
  <div class="footer">
    <p>DevSecOps Team @<a href="https://www.kariyer.net" target="_blank">kariyer.net</a></p>
    <div class="footer-divider"></div>
    <p>Generated on {{.ScanDate}}</p>
    <p>Report generation time: {{.GenerationTime}}</p>
  </div>
  
  <script>
    var categoriesList = [
      {{range .Categories}}
      { name: "{{.Name | lower}}", count: {{.Count}}, severity: "{{getSeverityName .Severity | lower}}" },
      {{end}}
    ];
    var categoriesData = {
      {{range .Categories}}
      "{{.Name | lower}}": {{.Count}},
      {{end}}
    };
  </script>
  
  <script>
    const ctx = document.getElementById('severityChart').getContext('2d');
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [
            {{index .SeverityCounts 4}},
            {{index .SeverityCounts 3}},
            {{index .SeverityCounts 2}},
            {{index .SeverityCounts 1}}
          ],
          backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#20c997']
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } }
      }
    });
    
    document.addEventListener('DOMContentLoaded', function() {
      const searchInput = document.getElementById('searchInput');
      const severityFilter = document.getElementById('severityFilter');
      const categoryFilter = document.getElementById('categoryFilter');
      const findingCards = document.querySelectorAll('.finding-card');
      const noResults = document.querySelector('.no-results');
      const categoryCard = document.getElementById('selectedCategoryCard');
      const severityCard = document.getElementById('selectedSeverityCard');
      
      function filterFindings() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedSeverity = severityFilter.value;
        const selectedCategory = categoryFilter.value;
        let visibleCount = 0;
        findingCards.forEach(card => {
          const content = card.textContent.toLowerCase();
          const cardSeverity = card.getAttribute('data-severity');
          const cardCategory = card.getAttribute('data-category');
          const matchesSearch = content.includes(searchTerm);
          const matchesSeverity = selectedSeverity === 'all' || cardSeverity === selectedSeverity;
          const matchesCategory = selectedCategory === 'all' || cardCategory === selectedCategory;
          if (matchesSearch && matchesSeverity && matchesCategory) {
            card.style.display = 'block';
            visibleCount++;
          } else {
            card.style.display = 'none';
          }
        });
        noResults.style.display = visibleCount === 0 ? 'block' : 'none';
      }
      
      searchInput.addEventListener('input', filterFindings);
      severityFilter.addEventListener('change', function() {
        filterFindings();
        var selected = this.value;
        if (selected === 'all') {
          severityCard.style.display = 'none';
        } else {
          var filtered = categoriesList.filter(function(cat) {
            return cat.severity === selected;
          });
          if (filtered.length > 0) {
            severityCard.style.display = 'block';
            var details = filtered.map(function(cat) {
              return cat.name + ": " + cat.count;
            }).join(" | ");
            severityCard.textContent = details;
          } else {
            severityCard.style.display = 'none';
          }
        }
      });
      categoryFilter.addEventListener('change', function() {
        filterFindings();
        var selected = this.value;
        if (selected === 'all') {
          categoryCard.style.display = 'none';
        } else {
          var count = categoriesData[selected] || 0;
          categoryCard.style.display = 'block';
          var selectedText = this.options[this.selectedIndex].text;
          categoryCard.textContent = selectedText + ": " + count;
        }
      });
    });
  </script>
</body>
</html>
`
	funcMap := template.FuncMap{
		"toLowerCase": strings.ToLower,
		"lower":       strings.ToLower,
		"getSeverityName": func(s SeverityLevel) string {
			switch s {
			case Critical:
				return "Critical"
			case High:
				return "High"
			case Medium:
				return "Medium"
			case Low:
				return "Low"
			default:
				return "Unknown"
			}
		},
		"getSeverity": getSeverity,
		"censor":      censor,
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("template parsing error: %v", err)
	}

	err = tmpl.Execute(reportFile, reportData)
	if err != nil {
		return fmt.Errorf("HTML raporu oluşturulurken hata: %v", err)
	}

	fmt.Printf("Güvenlik raporu '%s' dosyasına kaydedildi.\n", reportFileName)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Kullanım: go run main.go <dizin_yolu> [--report]")
		os.Exit(1)
	}

	directory := os.Args[1]
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		fmt.Printf("Geçersiz dizin: %s\n", directory)
		os.Exit(1)
	}

	generateReportFlag := false
	if len(os.Args) > 2 && os.Args[2] == "--report" {
		generateReportFlag = true
	}

	fmt.Printf("%s dizini taranıyor...\n\n", directory)
	findings, scannedFileCount := scanDirectoryParallel(directory)

	if len(findings) > 0 {
		fmt.Println("Uyarı! Aşağıdaki hassas bilgiler tespit edildi:")
		for _, f := range findings {
			fmt.Printf("Dosya: %s\nBulgu: %s\nEşleşme: %s\nSatır: %d\n%s\n",
				f.File, f.Name, f.Match, f.LineNumber, strings.Repeat("-", 40))
		}

		logFileName := logFindings(findings, directory)

		if generateReportFlag && logFileName != "" {
			fmt.Println("HTML raporu oluşturuluyor...")
			path, _ := os.Getwd()
			err := GenerateHTMLReport(path+"/"+logFileName, scannedFileCount)
			if err != nil {
				fmt.Printf("Rapor oluşturulurken hata: %v\n", err)
			} else {
				fmt.Println("HTML raporu başarıyla oluşturuldu.")
			}
		}

		os.Exit(1)
	} else {
		fmt.Println("Taramada herhangi bir hassas bilgi bulunamadı.")
		os.Exit(0)
	}
}
