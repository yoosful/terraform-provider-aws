package sagemaker_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sagemaker"
	"github.com/hashicorp/aws-sdk-go-base/tfawserr"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
)

func TestAccSageMakerEndpoint_basic(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_sagemaker_endpoint.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, sagemaker.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSagemakerEndpointDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSagemakerEndpointConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSagemakerEndpointExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
					resource.TestCheckResourceAttr(resourceName, "endpoint_config_name", rName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccSageMakerEndpoint_endpointName(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resourceName := "aws_sagemaker_endpoint.test"
	sagemakerEndpointConfigurationResourceName1 := "aws_sagemaker_endpoint_configuration.test"
	sagemakerEndpointConfigurationResourceName2 := "aws_sagemaker_endpoint_configuration.test2"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, sagemaker.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSagemakerEndpointDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSagemakerEndpointConfig(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSagemakerEndpointExists(resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "endpoint_config_name", sagemakerEndpointConfigurationResourceName1, "name"),
				),
			},
			{
				Config: testAccSagemakerEndpointConfigEndpointConfigNameUpdate(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSagemakerEndpointExists(resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "endpoint_config_name", sagemakerEndpointConfigurationResourceName2, "name"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccSageMakerEndpoint_tags(t *testing.T) {
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_sagemaker_endpoint.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, sagemaker.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckSagemakerEndpointDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccSagemakerEndpointConfigTags(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSagemakerEndpointExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.foo", "bar"),
				),
			},
			{
				Config: testAccSagemakerEndpointConfigTagsUpdate(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckSagemakerEndpointExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.bar", "baz"),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccCheckSagemakerEndpointDestroy(s *terraform.State) error {
	conn := acctest.Provider.Meta().(*conns.AWSClient).SageMakerConn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_sagemaker_endpoint" {
			continue
		}

		describeInput := &sagemaker.DescribeEndpointInput{
			EndpointName: aws.String(rs.Primary.ID),
		}

		_, err := conn.DescribeEndpoint(describeInput)

		if tfawserr.ErrMessageContains(err, "ValidationException", "") {
			continue
		}

		if err != nil {
			return err
		}

		return fmt.Errorf("SageMaker Endpoint (%s) still exists", rs.Primary.ID)
	}
	return nil
}

func testAccCheckSagemakerEndpointExists(n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("no SageMaker Endpoint ID is set")
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).SageMakerConn
		opts := &sagemaker.DescribeEndpointInput{
			EndpointName: aws.String(rs.Primary.ID),
		}
		_, err := conn.DescribeEndpoint(opts)
		if err != nil {
			return err
		}
		return nil
	}
}

func testAccSagemakerEndpointConfig_Base(rName string) string {
	return fmt.Sprintf(`
data "aws_iam_policy_document" "access" {
  statement {
    effect = "Allow"

    actions = [
      "cloudwatch:PutMetricData",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:CreateLogGroup",
      "logs:DescribeLogStreams",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "s3:GetObject",
    ]

    resources = ["*"]
  }
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["sagemaker.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

resource "aws_iam_role" "test" {
  name               = %[1]q
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy" "test" {
  role   = aws_iam_role.test.name
  policy = data.aws_iam_policy_document.access.json
}

resource "aws_s3_bucket" "test" {
  acl    = "private"
  bucket = %[1]q
}

resource "aws_s3_bucket_object" "test" {
  bucket = aws_s3_bucket.test.id
  key    = "model.tar.gz"
  source = "test-fixtures/sagemaker-tensorflow-serving-test-model.tar.gz"
}

data "aws_sagemaker_prebuilt_ecr_image" "test" {
  repository_name = "sagemaker-tensorflow-serving"
  image_tag       = "1.12-cpu"
}

resource "aws_sagemaker_model" "test" {
  name               = %[1]q
  execution_role_arn = aws_iam_role.test.arn

  primary_container {
    image          = data.aws_sagemaker_prebuilt_ecr_image.test.registry_path
    model_data_url = "https://${aws_s3_bucket.test.bucket_regional_domain_name}/${aws_s3_bucket_object.test.key}"
  }

  depends_on = [aws_iam_role_policy.test]
}

resource "aws_sagemaker_endpoint_configuration" "test" {
  name = %[1]q

  production_variants {
    initial_instance_count = 1
    initial_variant_weight = 1
    instance_type          = "ml.t2.medium"
    model_name             = aws_sagemaker_model.test.name
    variant_name           = "variant-1"
  }
}
`, rName)
}

func testAccSagemakerEndpointConfig(rName string) string {
	return testAccSagemakerEndpointConfig_Base(rName) + fmt.Sprintf(`
resource "aws_sagemaker_endpoint" "test" {
  endpoint_config_name = aws_sagemaker_endpoint_configuration.test.name
  name                 = %[1]q
}
`, rName)
}

func testAccSagemakerEndpointConfigEndpointConfigNameUpdate(rName string) string {
	return testAccSagemakerEndpointConfig_Base(rName) + fmt.Sprintf(`
resource "aws_sagemaker_endpoint_configuration" "test2" {
  name = "%[1]s2"

  production_variants {
    initial_instance_count = 1
    initial_variant_weight = 1
    instance_type          = "ml.t2.medium"
    model_name             = aws_sagemaker_model.test.name
    variant_name           = "variant-1"
  }
}

resource "aws_sagemaker_endpoint" "test" {
  endpoint_config_name = aws_sagemaker_endpoint_configuration.test2.name
  name                 = %[1]q
}
`, rName)
}

func testAccSagemakerEndpointConfigTags(rName string) string {
	return testAccSagemakerEndpointConfig_Base(rName) + fmt.Sprintf(`
resource "aws_sagemaker_endpoint" "test" {
  endpoint_config_name = aws_sagemaker_endpoint_configuration.test.name
  name                 = %[1]q

  tags = {
    foo = "bar"
  }
}
`, rName)
}

func testAccSagemakerEndpointConfigTagsUpdate(rName string) string {
	return testAccSagemakerEndpointConfig_Base(rName) + fmt.Sprintf(`
resource "aws_sagemaker_endpoint" "test" {
  endpoint_config_name = aws_sagemaker_endpoint_configuration.test.name
  name                 = %[1]q

  tags = {
    bar = "baz"
  }
}
`, rName)
}
