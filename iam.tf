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