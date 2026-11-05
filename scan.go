package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Scanner struct {
	EC2        EC2API
	ELBv2      ELBv2API
	Route53    Route53API
	IAM        IAMAPI
	S3         S3API
	HTTPClient *http.Client // for non-S3 OIDC liveness checks
	Config     Config
	Now        func() time.Time

	lbCache  []lbCacheEntry
	lbCached bool
}

type lbCacheEntry struct {
	VpcID string
	Name  string
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scanner) Scan(ctx context.Context) ([]InfraSet, error) {
	var vpcs []ec2types.Vpc
	var err error

	if s.Config.Target != "" {
		fmt.Fprintf(os.Stderr, "  Fetching target: %s\n", s.Config.Target)
		vpcs, err = s.fetchTargetVPCs(ctx, s.Config.Target)
	} else {
		fmt.Fprintf(os.Stderr, "  Fetching VPCs...\n")
		vpcs, err = s.fetchAllVPCs(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("fetching VPCs: %w", err)
	}

	grouped := s.groupByInfraID(vpcs)
	fmt.Fprintf(os.Stderr, "  Found %d VPCs, %d infra sets\n", len(vpcs), len(grouped))

	fmt.Fprintf(os.Stderr, "  Fetching OIDC providers...\n")
	oidcMap, err := s.fetchOIDCProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC providers: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  Found %d OIDC providers\n", len(oidcMap))

	fmt.Fprintf(os.Stderr, "  Classifying %d infra sets...\n", len(grouped))
	progress := 0
	leakedFound := 0
	var results []InfraSet
	for infraID, vpcInfos := range grouped {
		progress++
		if progress%10 == 0 {
			fmt.Fprintf(os.Stderr, "    %d/%d ...\n", progress, len(grouped))
		}

		limitReached := s.Config.Limit > 0 && leakedFound >= s.Config.Limit

		infraSet := InfraSet{
			InfraID: infraID,
			VPCs:    vpcInfos,
		}

		if verdict, reason := s.checkProtection(infraID, vpcInfos); verdict != "" {
			infraSet.Verdict = verdict
			infraSet.VerdictReason = reason
			results = append(results, infraSet)
			continue
		}

		s.resolveVPCCreationTime(ctx, &infraSet)

		if verdict, reason := s.checkAge(infraSet.VPCs, s.Config.MinAge); verdict != "" {
			infraSet.Verdict = verdict
			infraSet.VerdictReason = reason
			results = append(results, infraSet)
			continue
		}

		if limitReached {
			continue
		}

		if verdict, reason := s.checkOIDC(ctx, infraID, oidcMap); verdict != "" {
			infraSet.Verdict = verdict
			infraSet.VerdictReason = reason
			results = append(results, infraSet)
			continue
		}

		if verdict, reason, count := s.checkEC2Instances(ctx, infraID); verdict != "" {
			infraSet.Instances = count
			infraSet.Verdict = verdict
			infraSet.VerdictReason = reason
			results = append(results, infraSet)
			continue
		}

		// Shared VPC safety: even if this infra ID has no instances,
		// check if any of its VPCs have active instances from other infra IDs.
		if verdict, reason := s.checkVPCActiveInstances(ctx, vpcInfos); verdict != "" {
			infraSet.Verdict = verdict
			infraSet.VerdictReason = reason
			results = append(results, infraSet)
			continue
		}

		// If the infraID doesn't match any known CI pattern (hex ID or test name),
		// mark as UNCERTAIN — it could be a developer cluster or unknown origin.
		testType, _ := InferTestType(infraID)
		if testType == "" {
			infraSet.Verdict = VerdictUncertain
			infraSet.VerdictReason = fmt.Sprintf("no OIDC, no instances, but infraID %q does not match CI patterns — may belong to a developer", infraID)
			results = append(results, infraSet)
			continue
		}

		infraSet.Verdict = VerdictLeaked
		infraSet.VerdictReason = "no OIDC, no S3 doc, no EC2 instances"

		if info, ok := oidcMap[infraID]; ok {
			infraSet.OIDCProviders = append(infraSet.OIDCProviders, info.ARN)
			infraSet.VerdictReason += " (OIDC provider still exists)"
		}

		leakedFound++
		if s.Config.Limit > 0 {
			fmt.Fprintf(os.Stderr, "    LEAKED [%d/%d]: %s — inventorying sub-resources...\n", leakedFound, s.Config.Limit, infraID)
		} else {
			fmt.Fprintf(os.Stderr, "    LEAKED: %s — inventorying sub-resources...\n", infraID)
		}
		s.inventorySubResources(ctx, &infraSet)
		s.inventoryHostedZones(ctx, &infraSet)
		s.inventoryIAMRoles(ctx, &infraSet)

		if oldest := oldestVPC(infraSet.VPCs); !oldest.IsZero() {
			infraSet.Age = s.now().Sub(oldest)
		}

		results = append(results, infraSet)
	}

	// Orphaned resource scan: find IAM roles and OIDC providers
	// whose infra ID was not discovered from any VPC.
	if s.Config.Target == "" {
		knownInfraIDs := make(map[string]bool, len(grouped))
		for infraID := range grouped {
			knownInfraIDs[infraID] = true
		}
		orphaned, err := s.scanOrphanedResources(ctx, knownInfraIDs, oidcMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  WARN: orphaned resource scan failed: %v\n", err)
		} else if len(orphaned) > 0 {
			fmt.Fprintf(os.Stderr, "  Found %d orphaned infra sets (no VPC)\n", len(orphaned))
			results = append(results, orphaned...)
		}
	}

	return results, nil
}

// fetchTargetVPCs resolves a --target (VPC ID or infraID) to VPCs.
func (s *Scanner) fetchTargetVPCs(ctx context.Context, target string) ([]ec2types.Vpc, error) {
	if strings.HasPrefix(target, "vpc-") {
		out, err := s.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
			VpcIds: []string{target},
		})
		if err != nil {
			return nil, fmt.Errorf("VPC %s not found: %w", target, err)
		}
		return out.Vpcs, nil
	}

	infraID := strings.TrimSuffix(target, "-vpc")
	out, err := s.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("tag:Name"), Values: []string{infraID + "-vpc"}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("searching for infraID %s: %w", infraID, err)
	}
	if len(out.Vpcs) == 0 {
		return nil, fmt.Errorf("no VPC found for infraID %s (searched for Name tag '%s-vpc')", infraID, infraID)
	}
	return out.Vpcs, nil
}

func (s *Scanner) fetchAllVPCs(ctx context.Context) ([]ec2types.Vpc, error) {
	var all []ec2types.Vpc
	var nextToken *string
	for {
		out, err := s.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, out.Vpcs...)
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return all, nil
}

func (s *Scanner) groupByInfraID(vpcs []ec2types.Vpc) map[string][]VPCInfo {
	groups := make(map[string][]VPCInfo)
	for _, vpc := range vpcs {
		if aws.ToBool(vpc.IsDefault) {
			continue
		}

		vpcName := getTagValue(vpc.Tags, "Name")
		infraID := extractInfraID(vpc.Tags)

		doNotDelete := getTagValue(vpc.Tags, TagDoNotDelete) == "true"

		// VPCs without a k8s cluster tag are normally skipped, but protected
		// VPCs must ALWAYS appear so the protection gate can catch them.
		if infraID == "" {
			if !IsProtectedVPC(vpcName, s.Config.ProtectedVPCs) && !doNotDelete {
				continue
			}
			infraID = strings.TrimSuffix(vpcName, "-vpc")
		}

		info := VPCInfo{
			VPCID:          aws.ToString(vpc.VpcId),
			Name:           vpcName,
			CIDR:           aws.ToString(vpc.CidrBlock),
			State:          string(vpc.State),
			CreatedAt:      VPCCreateTime(vpc),
			ExpirationDate: parseExpirationDate(getTagValue(vpc.Tags, "expirationDate")),
			DoNotDelete:    getTagValue(vpc.Tags, TagDoNotDelete) == "true",
			CICluster:      getTagValue(vpc.Tags, TagCICluster),
			Source:         getTagValue(vpc.Tags, TagHypershiftSource),
			ClusterName:    getTagValue(vpc.Tags, TagHypershiftClusterName),
			ProwJobID:      getTagValue(vpc.Tags, TagHypershiftProwJobID),
		}

		groups[infraID] = append(groups[infraID], info)
	}
	return groups
}

func (s *Scanner) checkProtection(infraID string, vpcs []VPCInfo) (Verdict, string) {
	// Highest priority: do-not-delete tag is a hard block
	for _, vpc := range vpcs {
		if vpc.DoNotDelete {
			ciCluster := vpc.CICluster
			if ciCluster == "" {
				ciCluster = "unknown"
			}
			return VerdictProtected, fmt.Sprintf("do-not-delete=true (ci-cluster=%s)", ciCluster)
		}
	}

	// Protected VPC names
	for _, vpc := range vpcs {
		for _, protected := range s.Config.ProtectedVPCs {
			if vpc.Name == protected {
				return VerdictProtected, fmt.Sprintf("VPC name %q matches protected VPC", vpc.Name)
			}
		}
	}

	// Protected users
	for _, user := range s.Config.ProtectedUsers {
		if strings.Contains(infraID, user) {
			return VerdictProtected, fmt.Sprintf("infraID contains protected user %q", user)
		}
		for _, vpc := range vpcs {
			if strings.Contains(vpc.Name, user) {
				return VerdictProtected, fmt.Sprintf("VPC name %q contains protected user %q", vpc.Name, user)
			}
		}
	}

	return "", ""
}

func (s *Scanner) checkAge(vpcs []VPCInfo, minAge time.Duration) (Verdict, string) {
	// If any VPC has an expirationDate tag and it hasn't expired yet, it's too young
	for _, vpc := range vpcs {
		if !vpc.ExpirationDate.IsZero() && s.now().Before(vpc.ExpirationDate) {
			return VerdictTooYoung, fmt.Sprintf("expirationDate %s not reached yet", vpc.ExpirationDate.Format("2006-01-02 15:04"))
		}
	}

	oldest := oldestVPC(vpcs)
	if oldest.IsZero() {
		return VerdictUncertain, "could not determine VPC creation time from tags or resource timestamps"
	}

	age := s.now().Sub(oldest)
	if age < minAge {
		return VerdictTooYoung, fmt.Sprintf("VPC is %s old (min: %s)", age.Round(time.Minute), minAge)
	}

	return "", ""
}

type oidcProviderInfo struct {
	ARN    string
	Bucket string // empty for non-S3 providers
	Region string
	URL    string // full URL for non-S3 providers (e.g., "oidc.op1.openshiftapps.com/infraID")
}

func (s *Scanner) fetchOIDCProviders(ctx context.Context) (map[string]oidcProviderInfo, error) {
	result := make(map[string]oidcProviderInfo)

	out, err := s.IAM.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`([^.]+)\.s3\.([^.]+)\.amazonaws\.com/(.+)`)
	for _, p := range out.OpenIDConnectProviderList {
		arn := aws.ToString(p.Arn)
		parts := strings.SplitN(arn, "oidc-provider/", 2)
		if len(parts) < 2 {
			continue
		}
		providerURL := parts[1]
		m := re.FindStringSubmatch(providerURL)
		if m != nil {
			infraID := m[3]
			result[infraID] = oidcProviderInfo{
				ARN:    arn,
				Bucket: m[1],
				Region: m[2],
			}
			continue
		}

		// Non-S3 OIDC provider (e.g., oidc.op1.openshiftapps.com/infraID)
		// Extract infraID from the URL path.
		slashIdx := strings.Index(providerURL, "/")
		if slashIdx > 0 && slashIdx < len(providerURL)-1 {
			infraID := providerURL[slashIdx+1:]
			result[infraID] = oidcProviderInfo{
				ARN: arn,
				URL: providerURL,
			}
		}
	}

	return result, nil
}

func (s *Scanner) checkOIDC(ctx context.Context, infraID string, oidcMap map[string]oidcProviderInfo) (Verdict, string) {
	if info, ok := oidcMap[infraID]; ok {
		// Non-S3 provider: check HTTPS endpoint liveness
		if info.Bucket == "" && info.URL != "" {
			if s.checkHTTPSOIDC(ctx, info.URL) {
				return VerdictActive, fmt.Sprintf("HTTPS OIDC endpoint is live (%s)", info.URL)
			}
			return "", ""
		}

		isAllowed := false
		for _, bucket := range s.Config.AllowedBuckets {
			if strings.HasPrefix(info.Bucket, bucket) {
				isAllowed = true
				break
			}
		}
		if !isAllowed {
			return "", ""
		}

		if s.s3DocExists(ctx, info.Bucket, infraID) {
			return VerdictActive, fmt.Sprintf("S3 OIDC doc exists (bucket=%s)", info.Bucket)
		}
		return "", ""
	}

	for _, bucket := range s.Config.AllowedBuckets {
		if s.s3DocExists(ctx, bucket, infraID) {
			return VerdictActive, fmt.Sprintf("S3 OIDC doc found in bucket %s", bucket)
		}
	}

	return "", ""
}

// checkHTTPSOIDC performs an HTTPS GET to the OIDC discovery endpoint
// and returns true if the endpoint responds with HTTP 200 (cluster is active).
func (s *Scanner) checkHTTPSOIDC(ctx context.Context, providerURL string) bool {
	client := s.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	// providerURL is "host/infraID" — the discovery document lives under the full issuer URL.
	endpoint := fmt.Sprintf("https://%s/.well-known/openid-configuration", strings.TrimRight(providerURL, "/"))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (s *Scanner) s3DocExists(ctx context.Context, bucket, infraID string) bool {
	_, err := s.S3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(infraID + "/.well-known/openid-configuration"),
	})
	return err == nil
}

func (s *Scanner) checkEC2Instances(ctx context.Context, infraID string) (Verdict, string, int) {
	out, err := s.EC2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("tag:kubernetes.io/cluster/" + infraID),
				Values: []string{"owned"},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"pending", "running", "stopping", "stopped", "shutting-down"},
			},
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "    WARN: DescribeInstances failed for %s: %v\n", infraID, err)
		return VerdictUncertain, fmt.Sprintf("could not verify EC2 instances: %v", err), 0
	}

	count := 0
	for _, r := range out.Reservations {
		count += len(r.Instances)
	}

	if count > 0 {
		return VerdictActive, fmt.Sprintf("%d EC2 instances still running", count), count
	}

	return "", "", 0
}

// resolveVPCCreationTime fetches the earliest VPCE CreationTimestamp or ENI AttachTime
// for each VPC to determine when the infra was created. This is cheap (1 API call per VPC)
// and must run before the age gate.
func (s *Scanner) resolveVPCCreationTime(ctx context.Context, infra *InfraSet) {
	for i, vpc := range infra.VPCs {
		if !vpc.CreatedAt.IsZero() {
			continue
		}
		if out, err := s.EC2.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpc.VPCID}}},
		}); err == nil {
			for _, ep := range out.VpcEndpoints {
				if ep.CreationTimestamp != nil && (infra.VPCs[i].CreatedAt.IsZero() || ep.CreationTimestamp.Before(infra.VPCs[i].CreatedAt)) {
					infra.VPCs[i].CreatedAt = *ep.CreationTimestamp
				}
			}
		}
		if infra.VPCs[i].CreatedAt.IsZero() {
			if out, err := s.EC2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
				Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpc.VPCID}}},
			}); err == nil {
				for _, eni := range out.NetworkInterfaces {
					if eni.Attachment != nil && eni.Attachment.AttachTime != nil {
						if infra.VPCs[i].CreatedAt.IsZero() || eni.Attachment.AttachTime.Before(infra.VPCs[i].CreatedAt) {
							infra.VPCs[i].CreatedAt = *eni.Attachment.AttachTime
						}
					}
				}
			}
		}
	}
}

//nolint:gocyclo // sequential AWS inventory queries
func (s *Scanner) inventorySubResources(ctx context.Context, infra *InfraSet) {
	for i, vpc := range infra.VPCs {
		vpcID := vpc.VPCID

		if out, err := s.EC2.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		}); err == nil {
			infra.VPCs[i].Endpoints = len(out.VpcEndpoints)
			for _, ep := range out.VpcEndpoints {
				if ep.CreationTimestamp != nil && (infra.VPCs[i].CreatedAt.IsZero() || ep.CreationTimestamp.Before(infra.VPCs[i].CreatedAt)) {
					infra.VPCs[i].CreatedAt = *ep.CreationTimestamp
				}
			}
		}

		if out, err := s.EC2.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
			Filter: []ec2types.Filter{
				{Name: aws.String("vpc-id"), Values: []string{vpcID}},
				{Name: aws.String("state"), Values: []string{"available", "pending", "failed"}},
			},
		}); err == nil {
			infra.VPCs[i].NATGateways = len(out.NatGateways)
		}

		if out, err := s.EC2.DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{
			Filters: []ec2types.Filter{{Name: aws.String("attachment.vpc-id"), Values: []string{vpcID}}},
		}); err == nil {
			infra.VPCs[i].IGWs = len(out.InternetGateways)
		}

		if out, err := s.EC2.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		}); err == nil {
			infra.VPCs[i].Subnets = len(out.Subnets)
		}

		if out, err := s.EC2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		}); err == nil {
			nonDefault := 0
			for _, sg := range out.SecurityGroups {
				if aws.ToString(sg.GroupName) != "default" {
					nonDefault++
				}
			}
			infra.VPCs[i].SecurityGroups = nonDefault
		}

		if out, err := s.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		}); err == nil {
			nonMain := 0
			for _, rt := range out.RouteTables {
				isMain := false
				for _, a := range rt.Associations {
					if aws.ToBool(a.Main) {
						isMain = true
						break
					}
				}
				if !isMain {
					nonMain++
				}
			}
			infra.VPCs[i].RouteTables = nonMain
		}

		if out, err := s.EC2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
			Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcID}}},
		}); err == nil {
			infra.VPCs[i].ENIs = len(out.NetworkInterfaces)
			if infra.VPCs[i].CreatedAt.IsZero() {
				for _, eni := range out.NetworkInterfaces {
					if eni.Attachment != nil && eni.Attachment.AttachTime != nil {
						if infra.VPCs[i].CreatedAt.IsZero() || eni.Attachment.AttachTime.Before(infra.VPCs[i].CreatedAt) {
							infra.VPCs[i].CreatedAt = *eni.Attachment.AttachTime
						}
					}
				}
			}
		}

		infra.VPCs[i].ELBs = s.countLBsForVPC(ctx, vpcID)

		if out, err := s.EC2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{
			Filters: []ec2types.Filter{{Name: aws.String("domain"), Values: []string{"vpc"}}},
		}); err == nil {
			for _, addr := range out.Addresses {
				if s.eipBelongsToVPC(ctx, addr, vpcID) {
					infra.VPCs[i].EIPs++
				}
			}
		}
	}

	var nextToken *string
	for {
		out, err := s.EC2.DescribeVpcEndpointServiceConfigurations(ctx, &ec2.DescribeVpcEndpointServiceConfigurationsInput{
			NextToken: nextToken,
		})
		if err != nil {
			break
		}
		for _, svc := range out.ServiceConfigurations {
			svcInfraID := ""
			for _, tag := range svc.Tags {
				key := aws.ToString(tag.Key)
				if strings.HasPrefix(key, "kubernetes.io/cluster/") {
					svcInfraID = strings.TrimPrefix(key, "kubernetes.io/cluster/")
					break
				}
			}
			if svcInfraID == infra.InfraID {
				for i := range infra.VPCs {
					infra.VPCs[i].EndpointServices++
				}
			}
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
}

func (s *Scanner) eipBelongsToVPC(ctx context.Context, addr ec2types.Address, vpcID string) bool {
	eniID := aws.ToString(addr.NetworkInterfaceId)
	if eniID == "" {
		return false
	}
	out, err := s.EC2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{eniID},
	})
	if err != nil || len(out.NetworkInterfaces) == 0 {
		return false
	}
	return aws.ToString(out.NetworkInterfaces[0].VpcId) == vpcID
}

func (s *Scanner) inventoryHostedZones(ctx context.Context, infra *InfraSet) {
	var nextMarker *string
	for {
		out, err := s.Route53.ListHostedZones(ctx, &route53.ListHostedZonesInput{
			Marker: nextMarker,
		})
		if err != nil {
			return
		}

		for _, z := range out.HostedZones {
			name := strings.TrimSuffix(aws.ToString(z.Name), ".")
			zoneID := strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/")

			if ZoneMatchesInfra(name, infra.InfraID) {
				isPrivate := false
				if z.Config != nil {
					isPrivate = z.Config.PrivateZone
				}
				infra.HostedZones = append(infra.HostedZones, ZoneInfo{
					ZoneID:  zoneID,
					Name:    name,
					Private: isPrivate,
					Records: int(aws.ToInt64(z.ResourceRecordSetCount)),
				})
			}
		}

		if !out.IsTruncated {
			break
		}
		nextMarker = out.NextMarker
	}
}

var iamRoleSuffixes = []string{
	"-cloud-network-config-controller",
	"-aws-ebs-csi-driver-controller",
	"-openshift-image-registry",
	"-control-plane-operator",
	"-shared-vpc-control-plane",
	"-openshift-ingress",
	"-shared-vpc-ingress",
	"-cloud-controller",
	"-kms-provider",
	"-shared-role",
	"-karpenter",
	"-node-pool",
	"-worker-ROSA-Worker-Role",
	"-worker-role",
}

func (s *Scanner) inventoryIAMRoles(ctx context.Context, infra *InfraSet) {
	var nextMarker *string
	for {
		input := &iam.ListRolesInput{}
		if nextMarker != nil {
			input.Marker = nextMarker
		}
		out, err := s.IAM.ListRoles(ctx, input)
		if err != nil {
			return
		}

		for _, role := range out.Roles {
			roleName := aws.ToString(role.RoleName)
			for _, suffix := range iamRoleSuffixes {
				if strings.HasSuffix(roleName, suffix) {
					prefix := strings.TrimSuffix(roleName, suffix)
					if prefix == infra.InfraID {
						infra.IAMRoles = append(infra.IAMRoles, roleName)
					}
				}
			}
			if roleName == infra.InfraID {
				infra.IAMRoles = append(infra.IAMRoles, roleName)
			}
		}

		if !out.IsTruncated {
			break
		}
		nextMarker = out.Marker
	}
}

func (s *Scanner) fetchAllLoadBalancers(ctx context.Context) []lbCacheEntry {
	if s.lbCached {
		return s.lbCache
	}
	s.lbCached = true
	if s.ELBv2 == nil {
		return nil
	}
	var marker *string
	for {
		out, err := s.ELBv2.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			fmt.Fprintf(os.Stderr, "    WARN: list ELBs: %v\n", err)
			return nil
		}
		for _, lb := range out.LoadBalancers {
			s.lbCache = append(s.lbCache, lbCacheEntry{
				VpcID: aws.ToString(lb.VpcId),
				Name:  aws.ToString(lb.LoadBalancerName),
			})
		}
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	return s.lbCache
}

func (s *Scanner) countLBsForVPC(ctx context.Context, vpcID string) int {
	count := 0
	for _, lb := range s.fetchAllLoadBalancers(ctx) {
		if lb.VpcID == vpcID {
			count++
		}
	}
	return count
}

// checkVPCActiveInstances checks if any of the given VPCs have running instances
// from any infra ID (not just the one being classified). This protects shared VPCs
// where one cluster's resources are being cleaned up but another cluster is still active.
func (s *Scanner) checkVPCActiveInstances(ctx context.Context, vpcs []VPCInfo) (Verdict, string) {
	for _, vpc := range vpcs {
		out, err := s.EC2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			Filters: []ec2types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{vpc.VPCID},
				},
				{
					Name:   aws.String("instance-state-name"),
					Values: []string{"pending", "running", "stopping", "stopped"},
				},
			},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "    WARN: DescribeInstances failed for VPC %s: %v\n", vpc.VPCID, err)
			return VerdictUncertain, fmt.Sprintf("could not verify VPC %s active instances: %v", vpc.VPCID, err)
		}
		count := 0
		for _, r := range out.Reservations {
			count += len(r.Instances)
		}
		if count > 0 {
			return VerdictActive, fmt.Sprintf("VPC %s has %d active instances from other infra IDs", vpc.VPCID, count)
		}
	}
	return "", ""
}

// scanOrphanedResources discovers IAM roles and OIDC providers whose infra ID
// was not found in any VPC. These are "orphaned" resources left behind after
// the VPC was already deleted.
//
//nolint:gocyclo // orchestrates multiple AWS API calls for orphan detection
func (s *Scanner) scanOrphanedResources(ctx context.Context, knownInfraIDs map[string]bool, oidcMap map[string]oidcProviderInfo) ([]InfraSet, error) {
	orphanedSets := make(map[string]*InfraSet)

	// Track the oldest IAM role creation date per infra ID for age gating.
	orphanAge := make(map[string]time.Time)

	// Scan IAM roles for unknown infra IDs
	var nextMarker *string
	for {
		input := &iam.ListRolesInput{}
		if nextMarker != nil {
			input.Marker = nextMarker
		}
		out, err := s.IAM.ListRoles(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("listing IAM roles: %w", err)
		}

		for _, role := range out.Roles {
			roleName := aws.ToString(role.RoleName)
			for _, suffix := range iamRoleSuffixes {
				if strings.HasSuffix(roleName, suffix) {
					prefix := strings.TrimSuffix(roleName, suffix)
					if prefix != "" && !knownInfraIDs[prefix] {
						if _, exists := orphanedSets[prefix]; !exists {
							orphanedSets[prefix] = &InfraSet{
								InfraID:  prefix,
								Orphaned: true,
							}
						}
						orphanedSets[prefix].IAMRoles = append(orphanedSets[prefix].IAMRoles, roleName)
						// Track the oldest (earliest) role creation date
						if role.CreateDate != nil {
							if existing, ok := orphanAge[prefix]; !ok || role.CreateDate.Before(existing) {
								orphanAge[prefix] = *role.CreateDate
							}
						}
					}
				}
			}
		}

		if !out.IsTruncated {
			break
		}
		nextMarker = out.Marker
	}

	// Add OIDC providers for unknown infra IDs
	for infraID, info := range oidcMap {
		if knownInfraIDs[infraID] {
			continue
		}
		if _, exists := orphanedSets[infraID]; !exists {
			orphanedSets[infraID] = &InfraSet{
				InfraID:  infraID,
				Orphaned: true,
			}
		}
		orphanedSets[infraID].OIDCProviders = append(orphanedSets[infraID].OIDCProviders, info.ARN)
	}

	// Classify each orphaned infra set through the same gates
	var results []InfraSet
	for _, infra := range orphanedSets {
		// Protection check (user names in infraID)
		if verdict, reason := s.checkProtection(infra.InfraID, nil); verdict != "" {
			infra.Verdict = verdict
			infra.VerdictReason = reason
			results = append(results, *infra)
			continue
		}

		// Age gate: use the oldest IAM role creation date
		if created, ok := orphanAge[infra.InfraID]; ok {
			age := s.now().Sub(created)
			infra.Age = age
			if age < s.Config.MinAge {
				infra.Verdict = VerdictTooYoung
				infra.VerdictReason = fmt.Sprintf("orphaned resources are %s old (min: %s)", age.Round(time.Minute), s.Config.MinAge)
				results = append(results, *infra)
				continue
			}
		} else {
			infra.Verdict = VerdictUncertain
			infra.VerdictReason = "orphaned resources with no determinable age"
			results = append(results, *infra)
			continue
		}

		// OIDC check
		if verdict, reason := s.checkOIDC(ctx, infra.InfraID, oidcMap); verdict != "" {
			infra.Verdict = verdict
			infra.VerdictReason = reason
			results = append(results, *infra)
			continue
		}

		// EC2 instance check (tagged with this infra ID)
		if verdict, reason, count := s.checkEC2Instances(ctx, infra.InfraID); verdict != "" {
			infra.Instances = count
			infra.Verdict = verdict
			infra.VerdictReason = reason
			results = append(results, *infra)
			continue
		}

		// CI pattern check
		testType, _ := InferTestType(infra.InfraID)
		if testType == "" {
			infra.Verdict = VerdictUncertain
			infra.VerdictReason = fmt.Sprintf("orphaned resources, infraID %q does not match CI patterns", infra.InfraID)
			results = append(results, *infra)
			continue
		}

		// Trust policy fallback: try to verify OIDC from IAM role trust policies
		if len(infra.IAMRoles) > 0 {
			if bucket, _, found := s.checkOIDCFromTrustPolicy(ctx, infra.IAMRoles); found {
				if s.s3DocExists(ctx, bucket, infra.InfraID) {
					infra.Verdict = VerdictActive
					infra.VerdictReason = fmt.Sprintf("S3 OIDC doc found via trust policy (bucket=%s)", bucket)
					results = append(results, *infra)
					continue
				}
			}
		}

		infra.Verdict = VerdictLeaked
		infra.VerdictReason = "orphaned: no VPC, no OIDC doc, no EC2 instances"
		results = append(results, *infra)
	}

	return results, nil
}

// checkOIDCFromTrustPolicy reads the trust policy from one of the given IAM roles
// and extracts the OIDC issuer URL to determine the S3 bucket and region.
// This is a fallback for orphaned infra sets where the OIDC provider is already deleted.
func (s *Scanner) checkOIDCFromTrustPolicy(ctx context.Context, roles []string) (bucket, region string, found bool) {
	re := regexp.MustCompile(`([^.]+)\.s3\.([^.]+)\.amazonaws\.com`)

	for _, roleName := range roles {
		out, err := s.IAM.GetRole(ctx, &iam.GetRoleInput{
			RoleName: aws.String(roleName),
		})
		if err != nil {
			continue
		}
		if out.Role == nil || out.Role.AssumeRolePolicyDocument == nil {
			continue
		}

		// The trust policy document is URL-encoded
		policyDoc, err := url.QueryUnescape(aws.ToString(out.Role.AssumeRolePolicyDocument))
		if err != nil {
			continue
		}

		// Parse the policy JSON to find the OIDC issuer in Condition.StringEquals
		var policy struct {
			Statement []struct {
				Condition map[string]map[string]interface{} `json:"Condition"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(policyDoc), &policy); err != nil {
			continue
		}

		for _, stmt := range policy.Statement {
			for _, condMap := range stmt.Condition {
				for key := range condMap {
					m := re.FindStringSubmatch(key)
					if m != nil {
						return m[1], m[2], true
					}
				}
			}
		}
	}
	return "", "", false
}

// Tag constants, helpers, and utility functions are in tags.go
