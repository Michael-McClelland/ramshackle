resource "aws_iam_role" "test_role" {
  name = "test_role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    "Version" : "2008-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "token.actions.githubusercontent.com:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}









# {
# 	"Version": "2012-10-17",
# 	"Statement": [
# 		{
# 			"Sid": "VisualEditor0",
# 			"Effect": "Deny",
# 			"Action": "elasticloadbalancing:CreateLoadBalancer",
# 			"NotResource": [
# 				"arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
# 				"arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*",
# 				"arn:aws:elasticloadbalancing:*:*:loadbalancer/gwy/*/*"
# 			]
# 		}
# 	]
# }
