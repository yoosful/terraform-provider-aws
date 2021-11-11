package elasticsearch_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	elasticsearch "github.com/aws/aws-sdk-go/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/iam"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfelasticsearch "github.com/hashicorp/terraform-provider-aws/internal/service/elasticsearch"
)

func TestAccElasticsearchDomain_basic(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceName := "aws_elasticsearch_domain.test"
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(
						resourceName, "elasticsearch_version", "1.5"),
					resource.TestMatchResourceAttr(resourceName, "kibana_endpoint", regexp.MustCompile(`.*es\..*/_plugin/kibana/`)),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_requireHTTPS(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_DomainEndpointOptions(ri, true, "Policy-Min-TLS-1-0-2019-07"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists("aws_elasticsearch_domain.example", &domain),
					testAccCheckESDomainEndpointOptions(true, "Policy-Min-TLS-1-0-2019-07", &domain),
				),
			},
			{
				ResourceName:      "aws_elasticsearch_domain.example",
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_DomainEndpointOptions(ri, true, "Policy-Min-TLS-1-2-2019-07"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists("aws_elasticsearch_domain.example", &domain),
					testAccCheckESDomainEndpointOptions(true, "Policy-Min-TLS-1-2-2019-07", &domain),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_customEndpoint(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.example"
	customEndpoint := fmt.Sprintf("%s.example.com", resourceId)
	certResourceName := "aws_acm_certificate.example"
	certKey := acctest.TLSRSAPrivateKeyPEM(2048)
	certificate := acctest.TLSRSAX509SelfSignedCertificatePEM(certKey, customEndpoint)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_CustomEndpoint(ri, true, "Policy-Min-TLS-1-0-2019-07", true, customEndpoint, certKey, certificate),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "domain_endpoint_options.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "domain_endpoint_options.0.custom_endpoint_enabled", "true"),
					resource.TestCheckResourceAttrSet(resourceName, "domain_endpoint_options.0.custom_endpoint"),
					resource.TestCheckResourceAttrPair(resourceName, "domain_endpoint_options.0.custom_endpoint_certificate_arn", certResourceName, "arn"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_CustomEndpoint(ri, true, "Policy-Min-TLS-1-0-2019-07", true, customEndpoint, certKey, certificate),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESDomainEndpointOptions(true, "Policy-Min-TLS-1-0-2019-07", &domain),
					testAccCheckESCustomEndpoint(resourceName, true, customEndpoint, &domain),
				),
			},
			{
				Config: testAccESDomainConfig_CustomEndpoint(ri, true, "Policy-Min-TLS-1-0-2019-07", false, customEndpoint, certKey, certificate),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESDomainEndpointOptions(true, "Policy-Min-TLS-1-0-2019-07", &domain),
					testAccCheckESCustomEndpoint(resourceName, false, customEndpoint, &domain),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_Cluster_zoneAwareness(t *testing.T) {
	var domain1, domain2, domain3, domain4 elasticsearch.ElasticsearchDomainStatus
	rName := fmt.Sprintf("tf-acc-test-%s", sdkacctest.RandString(16)) // len = 28
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_ClusterConfig_ZoneAwarenessConfig_AvailabilityZoneCount(rName, 3),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain1),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_config.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_config.0.availability_zone_count", "3"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_enabled", "true"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     rName,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_ClusterConfig_ZoneAwarenessConfig_AvailabilityZoneCount(rName, 2),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain2),
					testAccCheckESDomainNotRecreated(&domain1, &domain2),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_config.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_config.0.availability_zone_count", "2"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_enabled", "true"),
				),
			},
			{
				Config: testAccESDomainConfig_ClusterConfig_ZoneAwarenessEnabled(rName, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain3),
					testAccCheckESDomainNotRecreated(&domain2, &domain3),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_config.#", "0"),
				),
			},
			{
				Config: testAccESDomainConfig_ClusterConfig_ZoneAwarenessConfig_AvailabilityZoneCount(rName, 3),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain4),
					testAccCheckESDomainNotRecreated(&domain3, &domain4),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_config.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_config.0.availability_zone_count", "3"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.zone_awareness_enabled", "true"),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_warm(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	rName := fmt.Sprintf("tf-acc-test-%s", sdkacctest.RandString(16)) // len = 28
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigWarm(rName, "ultrawarm1.medium.elasticsearch", false, 6),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_count", "0"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_type", ""),
				),
			},
			{
				Config: testAccESDomainConfigWarm(rName, "ultrawarm1.medium.elasticsearch", true, 6),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_count", "6"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_type", "ultrawarm1.medium.elasticsearch"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     rName,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfigWarm(rName, "ultrawarm1.medium.elasticsearch", true, 7),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_count", "7"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_type", "ultrawarm1.medium.elasticsearch"),
				),
			},
			{
				Config: testAccESDomainConfigWarm(rName, "ultrawarm1.large.elasticsearch", true, 7),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_count", "7"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.warm_type", "ultrawarm1.large.elasticsearch"),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_withDedicatedMaster(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceName := "aws_elasticsearch_domain.test"
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_WithDedicatedClusterMaster(ri, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_WithDedicatedClusterMaster(ri, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
			{
				Config: testAccESDomainConfig_WithDedicatedClusterMaster(ri, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_duplicate(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:   func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck: acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:  acctest.Providers,
		CheckDestroy: func(s *terraform.State) error {
			conn := acctest.Provider.Meta().(*conns.AWSClient).ElasticsearchConn
			_, err := conn.DeleteElasticsearchDomain(&elasticsearch.DeleteElasticsearchDomainInput{
				DomainName: aws.String(resourceId),
			})
			return err
		},
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					// Create duplicate
					conn := acctest.Provider.Meta().(*conns.AWSClient).ElasticsearchConn
					_, err := conn.CreateElasticsearchDomain(&elasticsearch.CreateElasticsearchDomainInput{
						DomainName: aws.String(resourceId),
						EBSOptions: &elasticsearch.EBSOptions{
							EBSEnabled: aws.Bool(true),
							VolumeSize: aws.Int64(10),
						},
					})
					if err != nil {
						t.Fatal(err)
					}

					err = tfelasticsearch.WaitForDomainCreation(conn, resourceId, resourceId)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: testAccESDomainConfig(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(
						resourceName, "elasticsearch_version", "1.5"),
				),
				ExpectError: regexp.MustCompile(`domain .+ already exists`),
			},
		},
	})
}

func TestAccElasticsearchDomain_v23(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigV23(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(
						resourceName, "elasticsearch_version", "2.3"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_complex(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_complex(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_vpc(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_vpc(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_VPC_update(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_vpc_update1(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESNumberOfSecurityGroups(1, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_vpc_update2(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESNumberOfSecurityGroups(2, &domain),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_internetToVPCEndpoint(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_internetToVpcEndpoint(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_AutoTuneOptions(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	autoTuneStartAtTime := testAccGetValidStartAtTime(t, "24h")
	resourceName := "aws_elasticsearch_domain.test"
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigWithAutoTuneOptions(ri, autoTuneStartAtTime),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(
						resourceName, "elasticsearch_version", "6.7"),
					resource.TestMatchResourceAttr(resourceName, "kibana_endpoint", regexp.MustCompile(`.*es\..*/_plugin/kibana/`)),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.desired_state", "ENABLED"),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.maintenance_schedule.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.maintenance_schedule.0.start_at", autoTuneStartAtTime),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.maintenance_schedule.0.duration.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.maintenance_schedule.0.duration.0.value", "2"),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.maintenance_schedule.0.duration.0.unit", "HOURS"),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.maintenance_schedule.0.cron_expression_for_recurrence", "cron(0 0 ? * 1 *)"),
					resource.TestCheckResourceAttr(resourceName, "auto_tune_options.0.rollback_on_disable", "NO_ROLLBACK"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_AdvancedSecurityOptions_userDB(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	domainName := sdkacctest.RandomWithPrefix("tf-test")
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_AdvancedSecurityOptionsUserDb(domainName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckAdvancedSecurityOptions(true, true, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     domainName,
				ImportStateVerify: true,
				// MasterUserOptions are not returned from DescribeElasticsearchDomainConfig
				ImportStateVerifyIgnore: []string{
					"advanced_security_options.0.internal_user_database_enabled",
					"advanced_security_options.0.master_user_options",
				},
			},
		},
	})
}

func TestAccElasticsearchDomain_AdvancedSecurityOptions_iam(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	domainName := sdkacctest.RandomWithPrefix("tf-test")
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_AdvancedSecurityOptionsIAM(domainName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckAdvancedSecurityOptions(true, false, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     domainName,
				ImportStateVerify: true,
				// MasterUserOptions are not returned from DescribeElasticsearchDomainConfig
				ImportStateVerifyIgnore: []string{
					"advanced_security_options.0.internal_user_database_enabled",
					"advanced_security_options.0.master_user_options",
				},
			},
		},
	})
}

func TestAccElasticsearchDomain_AdvancedSecurityOptions_disabled(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	domainName := sdkacctest.RandomWithPrefix("tf-test")
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_AdvancedSecurityOptionsDisabled(domainName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckAdvancedSecurityOptions(false, false, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     domainName,
				ImportStateVerify: true,
				// MasterUserOptions are not returned from DescribeElasticsearchDomainConfig
				ImportStateVerifyIgnore: []string{
					"advanced_security_options.0.internal_user_database_enabled",
					"advanced_security_options.0.master_user_options",
				},
			},
		},
	})
}

func TestAccElasticsearchDomain_LogPublishingOptions_indexSlowLogs(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_LogPublishingOptions(ri, elasticsearch.LogTypeIndexSlowLogs),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "log_publishing_options.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "log_publishing_options.*", map[string]string{
						"log_type": elasticsearch.LogTypeIndexSlowLogs,
					}),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_LogPublishingOptions_searchSlowLogs(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_LogPublishingOptions(ri, elasticsearch.LogTypeSearchSlowLogs),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "log_publishing_options.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "log_publishing_options.*", map[string]string{
						"log_type": elasticsearch.LogTypeSearchSlowLogs,
					}),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_LogPublishingOptions_esApplicationLogs(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_LogPublishingOptions(ri, elasticsearch.LogTypeEsApplicationLogs),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "log_publishing_options.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "log_publishing_options.*", map[string]string{
						"log_type": elasticsearch.LogTypeEsApplicationLogs,
					}),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_LogPublishingOptions_auditLogs(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_LogPublishingOptions(ri, elasticsearch.LogTypeAuditLogs),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "log_publishing_options.#", "1"),
					resource.TestCheckTypeSetElemNestedAttrs(resourceName, "log_publishing_options.*", map[string]string{
						"log_type": elasticsearch.LogTypeAuditLogs,
					}),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
				// MasterUserOptions are not returned from DescribeElasticsearchDomainConfig
				ImportStateVerifyIgnore: []string{"advanced_security_options.0.master_user_options"},
			},
		},
	})
}

func TestAccElasticsearchDomain_cognitoOptionsCreateAndRemove(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceName := "aws_elasticsearch_domain.test"
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			testAccPreCheckCognitoIdentityProvider(t)
			testAccPreCheckIamServiceLinkedRoleEs(t)
		},
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_CognitoOptions(ri, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESCognitoOptions(true, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_CognitoOptions(ri, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESCognitoOptions(false, &domain),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_cognitoOptionsUpdate(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(t)
			testAccPreCheckCognitoIdentityProvider(t)
			testAccPreCheckIamServiceLinkedRoleEs(t)
		},
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_CognitoOptions(ri, false),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESCognitoOptions(false, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_CognitoOptions(ri, true),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESCognitoOptions(true, &domain),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_policy(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	resourceName := "aws_elasticsearch_domain.test"
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigWithPolicy(ri, ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_EncryptAtRestDefault_key(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	resourceName := "aws_elasticsearch_domain.test"
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigWithEncryptAtRestDefaultKey(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESEncrypted(true, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_EncryptAtRestSpecify_key(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	resourceName := "aws_elasticsearch_domain.test"
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigWithEncryptAtRestWithKey(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESEncrypted(true, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_nodeToNodeEncryption(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	resourceName := "aws_elasticsearch_domain.test"
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigwithNodeToNodeEncryption(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					testAccCheckESNodetoNodeEncrypted(true, &domain),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_tags(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckELBDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "0"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_TagUpdate(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "2"),
					resource.TestCheckResourceAttr(resourceName, "tags.foo", "bar"),
					resource.TestCheckResourceAttr(resourceName, "tags.new", "type"),
				),
			},
		},
	})
}

func TestAccElasticsearchDomain_update(t *testing.T) {
	var input elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_ClusterUpdate(ri, 2, 22),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &input),
					testAccCheckESNumberOfInstances(2, &input),
					testAccCheckESSnapshotHour(22, &input),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_ClusterUpdate(ri, 4, 23),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &input),
					testAccCheckESNumberOfInstances(4, &input),
					testAccCheckESSnapshotHour(23, &input),
				),
			},
		}})
}

func TestAccElasticsearchDomain_UpdateVolume_type(t *testing.T) {
	var input elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_ClusterUpdateEBSVolume(ri, 24),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &input),
					testAccCheckESEBSVolumeEnabled(true, &input),
					testAccCheckESEBSVolumeSize(24, &input),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_ClusterUpdateInstanceStore(ri),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &input),
					testAccCheckESEBSVolumeEnabled(false, &input),
				),
			},
			{
				Config: testAccESDomainConfig_ClusterUpdateEBSVolume(ri, 12),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &input),
					testAccCheckESEBSVolumeEnabled(true, &input),
					testAccCheckESEBSVolumeSize(12, &input),
				),
			},
		}})
}

// Reference: https://github.com/hashicorp/terraform-provider-aws/issues/13867
func TestAccElasticsearchDomain_WithVolumeType_missing(t *testing.T) {
	var domain elasticsearch.ElasticsearchDomainStatus
	resourceName := "aws_elasticsearch_domain.test"
	rName := fmt.Sprintf("tf-acc-test-%s", sdkacctest.RandString(16))

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfigWithDisabledEBSAndVolumeType(rName, ""),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.instance_type", "i3.xlarge.elasticsearch"),
					resource.TestCheckResourceAttr(resourceName, "cluster_config.0.instance_count", "1"),
					resource.TestCheckResourceAttr(resourceName, "ebs_options.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "ebs_options.0.ebs_enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "ebs_options.0.volume_size", "0"),
					resource.TestCheckResourceAttr(resourceName, "ebs_options.0.volume_type", ""),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     rName,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccElasticsearchDomain_Update_version(t *testing.T) {
	var domain1, domain2, domain3 elasticsearch.ElasticsearchDomainStatus
	ri := sdkacctest.RandInt()
	resourceId := fmt.Sprintf("tf-test-%d", ri)
	resourceName := "aws_elasticsearch_domain.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t); testAccPreCheckIamServiceLinkedRoleEs(t) },
		ErrorCheck:   acctest.ErrorCheck(t, elasticsearch.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckESDomainDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccESDomainConfig_ClusterUpdateVersion(ri, "5.5"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain1),
					resource.TestCheckResourceAttr(resourceName, "elasticsearch_version", "5.5"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateId:     resourceId,
				ImportStateVerify: true,
			},
			{
				Config: testAccESDomainConfig_ClusterUpdateVersion(ri, "5.6"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain2),
					testAccCheckESDomainNotRecreated(&domain1, &domain2),
					resource.TestCheckResourceAttr(resourceName, "elasticsearch_version", "5.6"),
				),
			},
			{
				Config: testAccESDomainConfig_ClusterUpdateVersion(ri, "6.3"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckESDomainExists(resourceName, &domain3),
					testAccCheckESDomainNotRecreated(&domain2, &domain3),
					resource.TestCheckResourceAttr(resourceName, "elasticsearch_version", "6.3"),
				),
			},
		}})
}

func testAccCheckESDomainEndpointOptions(enforceHTTPS bool, tls string, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		options := status.DomainEndpointOptions
		if *options.EnforceHTTPS != enforceHTTPS {
			return fmt.Errorf("EnforceHTTPS differ. Given: %t, Expected: %t", *options.EnforceHTTPS, enforceHTTPS)
		}
		if *options.TLSSecurityPolicy != tls {
			return fmt.Errorf("TLSSecurityPolicy differ. Given: %s, Expected: %s", *options.TLSSecurityPolicy, tls)
		}
		return nil
	}
}

func testAccCheckESCustomEndpoint(n string, customEndpointEnabled bool, customEndpoint string, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}
		options := status.DomainEndpointOptions
		if *options.CustomEndpointEnabled != customEndpointEnabled {
			return fmt.Errorf("CustomEndpointEnabled differ. Given: %t, Expected: %t", *options.CustomEndpointEnabled, customEndpointEnabled)
		}
		if *options.CustomEndpointEnabled {
			if *options.CustomEndpoint != customEndpoint {
				return fmt.Errorf("CustomEndpoint differ. Given: %s, Expected: %s", *options.CustomEndpoint, customEndpoint)
			}
			customEndpointCertificateArn := rs.Primary.Attributes["domain_endpoint_options.0.custom_endpoint_certificate_arn"]
			if *options.CustomEndpointCertificateArn != customEndpointCertificateArn {
				return fmt.Errorf("CustomEndpointCertificateArn differ. Given: %s, Expected: %s", *options.CustomEndpointCertificateArn, customEndpointCertificateArn)
			}
		}
		return nil
	}
}

func testAccCheckESNumberOfSecurityGroups(numberOfSecurityGroups int, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		count := len(status.VPCOptions.SecurityGroupIds)
		if count != numberOfSecurityGroups {
			return fmt.Errorf("Number of security groups differ. Given: %d, Expected: %d", count, numberOfSecurityGroups)
		}
		return nil
	}
}

func testAccCheckESEBSVolumeSize(ebsVolumeSize int, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conf := status.EBSOptions
		if *conf.VolumeSize != int64(ebsVolumeSize) {
			return fmt.Errorf("EBS volume size differ. Given: %d, Expected: %d", *conf.VolumeSize, ebsVolumeSize)
		}
		return nil
	}
}

func testAccCheckESEBSVolumeEnabled(ebsEnabled bool, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conf := status.EBSOptions
		if *conf.EBSEnabled != ebsEnabled {
			return fmt.Errorf("EBS volume enabled. Given: %t, Expected: %t", *conf.EBSEnabled, ebsEnabled)
		}
		return nil
	}
}

func testAccCheckESSnapshotHour(snapshotHour int, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conf := status.SnapshotOptions
		if *conf.AutomatedSnapshotStartHour != int64(snapshotHour) {
			return fmt.Errorf("Snapshots start hour differ. Given: %d, Expected: %d", *conf.AutomatedSnapshotStartHour, snapshotHour)
		}
		return nil
	}
}

func testAccCheckESNumberOfInstances(numberOfInstances int, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conf := status.ElasticsearchClusterConfig
		if *conf.InstanceCount != int64(numberOfInstances) {
			return fmt.Errorf("Number of instances differ. Given: %d, Expected: %d", *conf.InstanceCount, numberOfInstances)
		}
		return nil
	}
}

func testAccCheckESEncrypted(encrypted bool, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conf := status.EncryptionAtRestOptions
		if *conf.Enabled != encrypted {
			return fmt.Errorf("Encrypt at rest not set properly. Given: %t, Expected: %t", *conf.Enabled, encrypted)
		}
		return nil
	}
}

func testAccCheckESNodetoNodeEncrypted(encrypted bool, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		options := status.NodeToNodeEncryptionOptions
		if aws.BoolValue(options.Enabled) != encrypted {
			return fmt.Errorf("Node-to-Node Encryption not set properly. Given: %t, Expected: %t", aws.BoolValue(options.Enabled), encrypted)
		}
		return nil
	}
}

func testAccCheckAdvancedSecurityOptions(enabled bool, userDbEnabled bool, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conf := status.AdvancedSecurityOptions

		if aws.BoolValue(conf.Enabled) != enabled {
			return fmt.Errorf(
				"AdvancedSecurityOptions.Enabled not set properly. Given: %t, Expected: %t",
				aws.BoolValue(conf.Enabled),
				enabled,
			)
		}

		if aws.BoolValue(conf.Enabled) {
			if aws.BoolValue(conf.InternalUserDatabaseEnabled) != userDbEnabled {
				return fmt.Errorf(
					"AdvancedSecurityOptions.InternalUserDatabaseEnabled not set properly. Given: %t, Expected: %t",
					aws.BoolValue(conf.InternalUserDatabaseEnabled),
					userDbEnabled,
				)
			}
		}

		return nil
	}
}

func testAccCheckESCognitoOptions(enabled bool, status *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conf := status.CognitoOptions
		if *conf.Enabled != enabled {
			return fmt.Errorf("CognitoOptions not set properly. Given: %t, Expected: %t", *conf.Enabled, enabled)
		}
		return nil
	}
}

func testAccCheckESDomainExists(n string, domain *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No ES Domain ID is set")
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).ElasticsearchConn
		opts := &elasticsearch.DescribeElasticsearchDomainInput{
			DomainName: aws.String(rs.Primary.Attributes["domain_name"]),
		}

		resp, err := conn.DescribeElasticsearchDomain(opts)
		if err != nil {
			return fmt.Errorf("Error describing domain: %s", err.Error())
		}

		*domain = *resp.DomainStatus

		return nil
	}
}

func testAccCheckESDomainNotRecreated(i, j *elasticsearch.ElasticsearchDomainStatus) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).ElasticsearchConn

		iConfig, err := conn.DescribeElasticsearchDomainConfig(&elasticsearch.DescribeElasticsearchDomainConfigInput{
			DomainName: i.DomainName,
		})
		if err != nil {
			return err
		}
		jConfig, err := conn.DescribeElasticsearchDomainConfig(&elasticsearch.DescribeElasticsearchDomainConfigInput{
			DomainName: j.DomainName,
		})
		if err != nil {
			return err
		}

		if !aws.TimeValue(iConfig.DomainConfig.ElasticsearchClusterConfig.Status.CreationDate).Equal(aws.TimeValue(jConfig.DomainConfig.ElasticsearchClusterConfig.Status.CreationDate)) {
			return fmt.Errorf("ES Domain was recreated")
		}

		return nil
	}
}

func testAccCheckESDomainDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_elasticsearch_domain" {
			continue
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).ElasticsearchConn
		opts := &elasticsearch.DescribeElasticsearchDomainInput{
			DomainName: aws.String(rs.Primary.Attributes["domain_name"]),
		}

		_, err := conn.DescribeElasticsearchDomain(opts)
		// Verify the error is what we want
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "ResourceNotFoundException" {
				continue
			}
			return err
		}
	}
	return nil
}

func testAccGetValidStartAtTime(t *testing.T, timeUntilStart string) string {
	n := time.Now().UTC()
	d, err := time.ParseDuration(timeUntilStart)
	if err != nil {
		t.Fatalf("err parsing timeUntilStart: %s", err)
	}
	return n.Add(d).Format(time.RFC3339)
}

func testAccPreCheckIamServiceLinkedRoleEs(t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).IAMConn
	dnsSuffix := acctest.Provider.Meta().(*conns.AWSClient).DNSSuffix

	input := &iam.ListRolesInput{
		PathPrefix: aws.String("/aws-service-role/es."),
	}

	var role *iam.Role
	err := conn.ListRolesPages(input, func(page *iam.ListRolesOutput, lastPage bool) bool {
		for _, r := range page.Roles {
			if strings.HasPrefix(aws.StringValue(r.Path), "/aws-service-role/es.") {
				role = r
			}
		}

		return !lastPage
	})

	if acctest.PreCheckSkipError(err) {
		t.Skipf("skipping acceptance testing: %s", err)
	}

	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}

	if role == nil {
		t.Fatalf("missing IAM Service Linked Role (es.%s), please create it in the AWS account and retry", dnsSuffix)
	}
}

func testAccESDomainConfig(randInt int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, randInt)
}

func testAccESDomainConfigWithAutoTuneOptions(randInt int, autoTuneStartAtTime string) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name           = "tf-test-%d"
  elasticsearch_version = "6.7"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  auto_tune_options {
    desired_state = "ENABLED"

    maintenance_schedule {
      start_at = "%s"
      duration {
        value = "2"
        unit  = "HOURS"
      }
      cron_expression_for_recurrence = "cron(0 0 ? * 1 *)"
    }

    rollback_on_disable = "NO_ROLLBACK"

  }
}
`, randInt, autoTuneStartAtTime)
}

func testAccESDomainConfigWithDisabledEBSAndVolumeType(rName, volumeType string) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name           = "%s"
  elasticsearch_version = "6.0"

  cluster_config {
    instance_type  = "i3.xlarge.elasticsearch"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = false
    volume_size = 0
    volume_type = "%s"
  }
}
`, rName, volumeType)
}

func testAccESDomainConfig_DomainEndpointOptions(randInt int, enforceHttps bool, tlsSecurityPolicy string) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "example" {
  domain_name = "tf-test-%[1]d"

  domain_endpoint_options {
    enforce_https       = %[2]t
    tls_security_policy = %[3]q
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, randInt, enforceHttps, tlsSecurityPolicy)
}

func testAccESDomainConfig_CustomEndpoint(randInt int, enforceHttps bool, tlsSecurityPolicy string, customEndpointEnabled bool, customEndpoint string, certKey string, certBody string) string {
	return fmt.Sprintf(`
resource "aws_acm_certificate" "example" {
  private_key      = "%[6]s"
  certificate_body = "%[7]s"
}

resource "aws_elasticsearch_domain" "example" {
  domain_name = "tf-test-%[1]d"

  domain_endpoint_options {
    enforce_https                   = %[2]t
    tls_security_policy             = %[3]q
    custom_endpoint_enabled         = %[4]t
    custom_endpoint                 = "%[5]s"
    custom_endpoint_certificate_arn = aws_acm_certificate.example.arn
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, randInt, enforceHttps, tlsSecurityPolicy, customEndpointEnabled, customEndpoint, acctest.TLSPEMEscapeNewlines(certKey), acctest.TLSPEMEscapeNewlines(certBody))
}

func testAccESDomainConfig_ClusterConfig_ZoneAwarenessConfig_AvailabilityZoneCount(rName string, availabilityZoneCount int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = %[1]q

  cluster_config {
    instance_type          = "t2.small.elasticsearch"
    instance_count         = 6
    zone_awareness_enabled = true

    zone_awareness_config {
      availability_zone_count = %[2]d
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, rName, availabilityZoneCount)
}

func testAccESDomainConfig_ClusterConfig_ZoneAwarenessEnabled(rName string, zoneAwarenessEnabled bool) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = %[1]q

  cluster_config {
    instance_type          = "t2.small.elasticsearch"
    instance_count         = 6
    zone_awareness_enabled = %[2]t
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, rName, zoneAwarenessEnabled)
}

func testAccESDomainConfigWarm(rName, warmType string, enabled bool, warmCnt int) string {
	warmConfig := ""
	if enabled {
		warmConfig = fmt.Sprintf(`
    warm_count = %[1]d
    warm_type = %[2]q
`, warmCnt, warmType)
	}

	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name           = %[1]q
  elasticsearch_version = "6.8"

  cluster_config {
    zone_awareness_enabled   = true
    instance_type            = "c5.large.elasticsearch"
    instance_count           = "3"
    dedicated_master_enabled = true
    dedicated_master_count   = "3"
    dedicated_master_type    = "c5.large.elasticsearch"
    warm_enabled             = %[2]t

    %[3]s

    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, rName, enabled, warmConfig)
}

func testAccESDomainConfig_WithDedicatedClusterMaster(randInt int, enabled bool) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  cluster_config {
    instance_type            = "t2.small.elasticsearch"
    instance_count           = "1"
    dedicated_master_enabled = %t
    dedicated_master_count   = "3"
    dedicated_master_type    = "t2.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, randInt, enabled)
}

func testAccESDomainConfig_ClusterUpdate(randInt, instanceInt, snapshotInt int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  advanced_options = {
    "indices.fielddata.cache.size" = 80
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  cluster_config {
    instance_count         = %d
    zone_awareness_enabled = true
    instance_type          = "t2.small.elasticsearch"
  }

  snapshot_options {
    automated_snapshot_start_hour = %d
  }

  timeouts {
    update = "180m"
  }
}
`, randInt, instanceInt, snapshotInt)
}

func testAccESDomainConfig_ClusterUpdateEBSVolume(randInt, volumeSize int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  elasticsearch_version = "6.0"

  advanced_options = {
    "indices.fielddata.cache.size" = 80
  }

  ebs_options {
    ebs_enabled = true
    volume_size = %d
  }

  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
    instance_type          = "t2.small.elasticsearch"
  }
}
`, randInt, volumeSize)
}

func testAccESDomainConfig_ClusterUpdateVersion(randInt int, version string) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  elasticsearch_version = "%v"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  cluster_config {
    instance_count         = 1
    zone_awareness_enabled = false
    instance_type          = "t2.small.elasticsearch"
  }
}
`, randInt, version)
}

func testAccESDomainConfig_ClusterUpdateInstanceStore(randInt int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  elasticsearch_version = "6.0"

  advanced_options = {
    "indices.fielddata.cache.size" = 80
  }

  ebs_options {
    ebs_enabled = false
  }

  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
    instance_type          = "i3.large.elasticsearch"
  }
}
`, randInt)
}

func testAccESDomainConfig_TagUpdate(randInt int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    foo = "bar"
    new = "type"
  }
}
`, randInt)
}

func testAccESDomainConfigWithPolicy(randESId int, randRoleId int) string {
	return fmt.Sprintf(`
data "aws_partition" "current" {
}

resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  access_policies = <<CONFIG
  {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "${aws_iam_role.example_role.arn}"
      },
      "Action": "es:*",
      "Resource": "arn:${data.aws_partition.current.partition}:es:*"
    }
  ]
  }
CONFIG
}

resource "aws_iam_role" "example_role" {
  name               = "es-domain-role-%d"
  assume_role_policy = data.aws_iam_policy_document.instance-assume-role-policy.json
}

data "aws_iam_policy_document" "instance-assume-role-policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.${data.aws_partition.current.dns_suffix}"]
    }
  }
}
`, randESId, randRoleId)
}

func testAccESDomainConfigWithEncryptAtRestDefaultKey(randESId int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  elasticsearch_version = "6.0"

  # Encrypt at rest requires m4/c4/r4/i2 instances. See http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-supported-instance-types.html
  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled = true
  }
}
`, randESId)
}

func testAccESDomainConfigWithEncryptAtRestWithKey(randESId int) string {
	return fmt.Sprintf(`
resource "aws_kms_key" "es" {
  description             = "kms-key-for-tf-test-%d"
  deletion_window_in_days = 7
}

resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  elasticsearch_version = "6.0"

  # Encrypt at rest requires m4/c4/r4/i2 instances. See http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-supported-instance-types.html
  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.es.key_id
  }
}
`, randESId, randESId)
}

func testAccESDomainConfigwithNodeToNodeEncryption(randInt int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  elasticsearch_version = "6.0"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  node_to_node_encryption {
    enabled = true
  }
}
`, randInt)
}

func testAccESDomainConfig_complex(randInt int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  advanced_options = {
    "indices.fielddata.cache.size" = 80
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
    instance_type          = "t2.small.elasticsearch"
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  tags = {
    bar = "complex"
  }
}
`, randInt)
}

func testAccESDomainConfigV23(randInt int) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  elasticsearch_version = "2.3"
}
`, randInt)
}

func testAccESDomainConfig_vpc(randInt int) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

resource "aws_vpc" "elasticsearch_in_vpc" {
  cidr_block = "192.168.0.0/22"

  tags = {
    Name = "terraform-testacc-elasticsearch-domain-in-vpc"
  }
}

resource "aws_subnet" "first" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "192.168.0.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-first"
  }
}

resource "aws_subnet" "second" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "192.168.1.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-second"
  }
}

resource "aws_security_group" "first" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_security_group" "second" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
    instance_type          = "t2.small.elasticsearch"
  }

  vpc_options {
    security_group_ids = [aws_security_group.first.id, aws_security_group.second.id]
    subnet_ids         = [aws_subnet.first.id, aws_subnet.second.id]
  }
}
`, randInt)
}

func testAccESDomainConfig_vpc_update1(randInt int) string {
	return acctest.ConfigCompose(
		acctest.ConfigAvailableAZsNoOptIn(),
		fmt.Sprintf(`
resource "aws_vpc" "elasticsearch_in_vpc" {
  cidr_block = "192.168.0.0/22"

  tags = {
    Name = "terraform-testacc-elasticsearch-domain-in-vpc-update"
  }
}

resource "aws_subnet" "az1_first" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "192.168.0.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az1-first"
  }
}

resource "aws_subnet" "az2_first" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "192.168.1.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az2-first"
  }
}

resource "aws_subnet" "az1_second" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "192.168.2.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az1-second"
  }
}

resource "aws_subnet" "az2_second" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "192.168.3.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az2-second"
  }
}

resource "aws_security_group" "first" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_security_group" "second" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%[1]d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
    instance_type          = "t2.small.elasticsearch"
  }

  vpc_options {
    security_group_ids = [aws_security_group.first.id]
    subnet_ids         = [aws_subnet.az1_first.id, aws_subnet.az2_first.id]
  }
}
`, randInt))
}

func testAccESDomainConfig_vpc_update2(randInt int) string {
	return acctest.ConfigCompose(
		acctest.ConfigAvailableAZsNoOptIn(),
		fmt.Sprintf(`
resource "aws_vpc" "elasticsearch_in_vpc" {
  cidr_block = "192.168.0.0/22"

  tags = {
    Name = "terraform-testacc-elasticsearch-domain-in-vpc-update"
  }
}

resource "aws_subnet" "az1_first" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "192.168.0.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az1-first"
  }
}

resource "aws_subnet" "az2_first" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "192.168.1.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az2-first"
  }
}

resource "aws_subnet" "az1_second" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "192.168.2.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az1-second"
  }
}

resource "aws_subnet" "az2_second" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "192.168.3.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-in-vpc-update-az2-second"
  }
}

resource "aws_security_group" "first" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_security_group" "second" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%[1]d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
    instance_type          = "t2.small.elasticsearch"
  }

  vpc_options {
    security_group_ids = [aws_security_group.first.id, aws_security_group.second.id]
    subnet_ids         = [aws_subnet.az1_second.id, aws_subnet.az2_second.id]
  }
}
`, randInt))
}

func testAccESDomainConfig_internetToVpcEndpoint(randInt int) string {
	return fmt.Sprintf(`
data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

resource "aws_vpc" "elasticsearch_in_vpc" {
  cidr_block = "192.168.0.0/22"

  tags = {
    Name = "terraform-testacc-elasticsearch-domain-internet-to-vpc-endpoint"
  }
}

resource "aws_subnet" "first" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "192.168.0.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-internet-to-vpc-endpoint-first"
  }
}

resource "aws_subnet" "second" {
  vpc_id            = aws_vpc.elasticsearch_in_vpc.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = "192.168.1.0/24"

  tags = {
    Name = "tf-acc-elasticsearch-domain-internet-to-vpc-endpoint-second"
  }
}

resource "aws_security_group" "first" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_security_group" "second" {
  vpc_id = aws_vpc.elasticsearch_in_vpc.id
}

resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%d"

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  cluster_config {
    instance_count         = 2
    zone_awareness_enabled = true
    instance_type          = "t2.small.elasticsearch"
  }

  vpc_options {
    security_group_ids = [aws_security_group.first.id, aws_security_group.second.id]
    subnet_ids         = [aws_subnet.first.id, aws_subnet.second.id]
  }
}
`, randInt)
}

func testAccESDomainConfig_AdvancedSecurityOptionsUserDb(domainName string) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name           = "%s"
  elasticsearch_version = "7.1"

  cluster_config {
    instance_type = "r5.large.elasticsearch"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "testmasteruser"
      master_user_password = "Barbarbarbar1!"
    }
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  node_to_node_encryption {
    enabled = true
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, domainName)
}

func testAccESDomainConfig_AdvancedSecurityOptionsIAM(domainName string) string {
	return fmt.Sprintf(`
resource "aws_iam_user" "es_master_user" {
  name = "%s"
}

resource "aws_elasticsearch_domain" "test" {
  domain_name           = "%s"
  elasticsearch_version = "7.1"

  cluster_config {
    instance_type = "r5.large.elasticsearch"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = aws_iam_user.es_master_user.arn
    }
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  node_to_node_encryption {
    enabled = true
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, sdkacctest.RandomWithPrefix("es-master-user"), domainName)
}

func testAccESDomainConfig_AdvancedSecurityOptionsDisabled(domainName string) string {
	return fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name           = "%s"
  elasticsearch_version = "7.1"

  cluster_config {
    instance_type = "r5.large.elasticsearch"
  }

  advanced_security_options {
    enabled                        = false
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "testmasteruser"
      master_user_password = "Barbarbarbar1!"
    }
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  node_to_node_encryption {
    enabled = true
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}
`, domainName)
}

func testAccESDomain_LogPublishingOptions_BaseConfig(randInt int) string {
	return fmt.Sprintf(`
data "aws_partition" "current" {
}

resource "aws_cloudwatch_log_group" "test" {
  name = "tf-test-%[1]d"
}

resource "aws_cloudwatch_log_resource_policy" "example" {
  policy_name = "tf-cwlp-%[1]d"

  policy_document = <<CONFIG
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.${data.aws_partition.current.dns_suffix}"
      },
      "Action": [
        "logs:PutLogEvents",
        "logs:PutLogEventsBatch",
        "logs:CreateLogStream"
      ],
      "Resource": "arn:${data.aws_partition.current.partition}:logs:*"
    }
  ]
}
CONFIG
}
`, randInt)
}

func testAccESDomainConfig_LogPublishingOptions(randInt int, logType string) string {
	var auditLogsConfig string
	if logType == elasticsearch.LogTypeAuditLogs {
		auditLogsConfig = `
	  	advanced_security_options {
			enabled                        = true
			internal_user_database_enabled = true
			master_user_options {
			  master_user_name     = "testmasteruser"
			  master_user_password = "Barbarbarbar1!"
			}
	  	}
	
		domain_endpoint_options {
	  		enforce_https       = true
	  		tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
		}
	
		encrypt_at_rest {
			enabled = true
		}
	
		node_to_node_encryption {
			enabled = true
		}`
	}
	return acctest.ConfigCompose(testAccESDomain_LogPublishingOptions_BaseConfig(randInt), fmt.Sprintf(`
resource "aws_elasticsearch_domain" "test" {
  domain_name           = "tf-test-%d"
  elasticsearch_version = "7.1" # needed for ESApplication/Audit Log Types

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

    %s

  log_publishing_options {
    log_type                 = "%s"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.test.arn
  }
}
`, randInt, auditLogsConfig, logType))
}

func testAccESDomainConfig_CognitoOptions(randInt int, includeCognitoOptions bool) string {

	var cognitoOptions string
	if includeCognitoOptions {
		cognitoOptions = `
		cognito_options {
			enabled          = true
			user_pool_id     = aws_cognito_user_pool.example.id
			identity_pool_id = aws_cognito_identity_pool.example.id
			role_arn         = aws_iam_role.example.arn
		}`
	} else {
		cognitoOptions = ""
	}

	return fmt.Sprintf(`
data "aws_partition" "current" {
}

resource "aws_cognito_user_pool" "example" {
  name = "tf-test-%[1]d"
}

resource "aws_cognito_user_pool_domain" "example" {
  domain       = "tf-test-%[1]d"
  user_pool_id = aws_cognito_user_pool.example.id
}

resource "aws_cognito_identity_pool" "example" {
  identity_pool_name               = "tf_test_%[1]d"
  allow_unauthenticated_identities = false

  lifecycle {
    ignore_changes = [cognito_identity_providers]
  }
}

resource "aws_iam_role" "example" {
  name               = "tf-test-%[1]d"
  path               = "/service-role/"
  assume_role_policy = data.aws_iam_policy_document.assume-role-policy.json
}

data "aws_iam_policy_document" "assume-role-policy" {
  statement {
    sid     = ""
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["es.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "example" {
  role       = aws_iam_role.example.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonESCognitoAccess"
}

resource "aws_elasticsearch_domain" "test" {
  domain_name = "tf-test-%[1]d"

  elasticsearch_version = "6.0"

	%s

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  depends_on = [
    aws_iam_role.example,
    aws_iam_role_policy_attachment.example,
  ]
}
`, randInt, cognitoOptions)
}

func testAccPreCheckCognitoIdentityProvider(t *testing.T) {
	conn := acctest.Provider.Meta().(*conns.AWSClient).CognitoIDPConn

	input := &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int64(1),
	}

	_, err := conn.ListUserPools(input)

	if acctest.PreCheckSkipError(err) {
		t.Skipf("skipping acceptance testing: %s", err)
	}

	if err != nil {
		t.Fatalf("unexpected PreCheck error: %s", err)
	}
}

func testAccCheckELBDestroy(s *terraform.State) error {
	conn := acctest.Provider.Meta().(*conns.AWSClient).ELBConn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_elb" {
			continue
		}

		describe, err := conn.DescribeLoadBalancers(&elb.DescribeLoadBalancersInput{
			LoadBalancerNames: []*string{aws.String(rs.Primary.ID)},
		})

		if err == nil {
			if len(describe.LoadBalancerDescriptions) != 0 &&
				*describe.LoadBalancerDescriptions[0].LoadBalancerName == rs.Primary.ID {
				return fmt.Errorf("ELB still exists")
			}
		}

		// Verify the error
		providerErr, ok := err.(awserr.Error)
		if !ok {
			return err
		}

		if providerErr.Code() != elb.ErrCodeAccessPointNotFoundException {
			return fmt.Errorf("Unexpected error: %s", err)
		}
	}

	return nil
}
