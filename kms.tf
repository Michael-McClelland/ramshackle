data "aws_iam_policy_document" "pass1" {

  statement {
    principals {
      type = "AWS"
      identifiers = [
        "*"
      ]
    }
    effect = "Allow"
    actions = [
      "kms:Update*",
      "kms:UntagResource",
      "kms:TagResource",
      "kms:SynchronizeMultiRegionKey",
      "kms:ScheduleKeyDeletion",
      "kms:ReplicateKey",
      "kms:PutKeyPolicy",
      "kms:List*",
      "kms:Get*",
      "kms:Enable*",
      "kms:Disable*",
      "kms:Describe*",
      "kms:DeleteAlias",
      "kms:CreateAlias",
      "kms:CancelKeyDeletion"
    ]
    resources = [
      "*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["${data.aws_organizations_organization.current.id}"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = ["${data.aws_iam_session_context.current.issuer_arn}"]
    }
  }
}

resource "aws_kms_key" "pass1" {
  description                        = "pass1"
  deletion_window_in_days            = 7
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  policy                             = data.aws_iam_policy_document.pass1.json
  bypass_policy_lockout_safety_check = false
  is_enabled                         = true
  enable_key_rotation                = true
}


resource "aws_kms_key" "pass2" {
  description = "fail5"
}

resource "aws_kms_key_policy" "pass2" {
  key_id = aws_kms_key.pass2.id
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "pass2"
    Statement = [
      {
        Sid = "pass2"
        Principal = {
          AWS = "*"
        }
        Effect   = "Allow"
        Action   = "kms:*"
        Resource = "*"
        "Condition" : {
          "StringEquals" : {
            "aws:PrincipalOrgID" : "${data.aws_organizations_organization.current.id}",
            "aws:PrincipalArn" : "${data.aws_iam_session_context.current.issuer_arn}"
          }
        }
      },
    ]
  })
}

resource "aws_kms_key" "pass3" {
  description                        = "pass3"
  deletion_window_in_days            = 7
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  policy                             = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "pass3",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
              "kms:Update*",
              "kms:UntagResource",
              "kms:TagResource",
              "kms:SynchronizeMultiRegionKey",
              "kms:ScheduleKeyDeletion",
              "kms:ReplicateKey",
              "kms:PutKeyPolicy",
              "kms:List*",
              "kms:Get*",
              "kms:Enable*",
              "kms:Disable*",
              "kms:Describe*",
              "kms:DeleteAlias",
              "kms:CreateAlias",
              "kms:CancelKeyDeletion"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": [
                        "${data.aws_iam_session_context.current.issuer_arn}"
                    ]
                }
            }
        }
    ]
}
POLICY
  bypass_policy_lockout_safety_check = false
  is_enabled                         = false
  enable_key_rotation                = true

}

data "aws_iam_policy_document" "fail1" {

  statement {
    principals {
      type = "AWS"
      identifiers = [
        "*"
      ]
    }
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    resources = [
      "*",
    ]
  }

}

resource "aws_kms_key" "fail1" {
  description                        = "fail1"
  deletion_window_in_days            = 7
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  policy                             = data.aws_iam_policy_document.fail1.json
  bypass_policy_lockout_safety_check = false
  is_enabled                         = true
  enable_key_rotation                = true
}

resource "aws_kms_key" "fail2" {
  description                        = "fail2"
  deletion_window_in_days            = 7
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  policy                             = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ABasicBadPolicyExampleTest",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:Update*",
                "kms:UntagResource",
                "kms:TagResource",
                "kms:SynchronizeMultiRegionKey",
                "kms:ScheduleKeyDeletion",
                "kms:ReplicateKey",
                "kms:PutKeyPolicy",
                "kms:List*",
                "kms:Get*",
                "kms:Enable*",
                "kms:Disable*",
                "kms:Describe*",
                "kms:DeleteAlias",
                "kms:CreateAlias",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowMacietoDecryptheKey",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::398930073421:root"
            },
            "Action": [
                "kms:List*",
                "kms:GetKeyRotationStatus",
                "kms:GetKeyPolicy",
                "kms:Describe*",
                "kms:Decrypt"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": "arn:aws:iam::398930073421:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
                }
            }
        },
        {
            "Sid": "AllowConfigandAccessAnalyzertoReadKeyAttributes",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::398930073421:root"
            },
            "Action": [
                "kms:List*",
                "kms:GetKeyRotationStatus",
                "kms:GetKeyPolicy",
                "kms:Describe*"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::398930073421:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer",
                        "arn:aws:iam::398930073421:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
                    ]
                }
            }
        }
    ]
}
POLICY
  bypass_policy_lockout_safety_check = false
  is_enabled                         = false
  enable_key_rotation                = false

}

resource "aws_kms_key" "fail3" {
  description             = "fail3"
  deletion_window_in_days = 30
  policy                  = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": [
                "kms:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AdministrativePermissionsForRolethatCreatedKey",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": [
                "kms:Update*",
                "kms:UntagResource",
                "kms:TagResource",
                "kms:SynchronizeMultiRegionKey",
                "kms:ScheduleKeyDeletion",
                "kms:ReplicateKey",
                "kms:PutKeyPolicy",
                "kms:List*",
                "kms:Get*",
                "kms:Enable*",
                "kms:Disable*",
                "kms:Describe*",
                "kms:DeleteAlias",
                "kms:CreateAlias",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalOrgID": "${data.aws_organizations_organization.current.id}",
                    "aws:PrincipalArn": "${data.aws_iam_session_context.current.issuer_arn}"
                }
            }
        },
        {
            "Sid": "RecoveryAndTDIRRolePermissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": [
                "kms:Update*",
                "kms:UntagResource",
                "kms:TagResource",
                "kms:SynchronizeMultiRegionKey",
                "kms:ScheduleKeyDeletion",
                "kms:ReplicateKey",
                "kms:PutKeyPolicy",
                "kms:List*",
                "kms:Get*",
                "kms:Enable*",
                "kms:Disable*",
                "kms:Describe*",
                "kms:DeleteAlias",
                "kms:CreateAlias",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": "${data.aws_caller_identity.current.id}",
                    "aws:PrincipalOrgID": "${data.aws_organizations_organization.current.id}",
                    "aws:PrincipalArn": [
                        "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/recoveryrole",
                        "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/incident-response-role"
                    ]
                }
            }
        },
        {
            "Sid": "lambdadecryptvariables",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": "kms:CreateGrant",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:EncryptionContext:${data.aws_partition.current.partition}:lambda:FunctionArn": [
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-format-eventbridge-input",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-check-snapshots",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-create-streaming-instance",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-check-instance-managed",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-run-command-stream-snapshot-to-s3",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-wait-run-command",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-create-sidecar-volume-instance",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-run-command-stream-sidecar-volume-snapshot-to-ec2",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-prepare-and-attach-volume",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-run-command-stream-memory-capture-to-s3"
                    ],
                    "kms:GrantConstraintType": "EncryptionContextEquals",
                    "kms:ViaService": "lambda.${data.aws_region.current.id}.amazonaws.com"
                },
                "ForAllValues:StringEquals": {
                    "kms:GrantOperations": [
                        "Decrypt",
                        "RetireGrant"
                    ]
                },
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        },
        {
            "Sid": "pipelinevariablemanagement",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:EncryptionContext:${data.aws_partition.current.partition}:lambda:FunctionArn": [
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-format-eventbridge-input",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-check-snapshots",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-create-streaming-instance",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-check-instance-managed",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-run-command-stream-snapshot-to-s3",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-wait-run-command",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-create-sidecar-volume-instance",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-run-command-stream-sidecar-volume-snapshot-to-ec2",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-prepare-and-attach-volume",
                        "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:function:tdir-run-command-stream-memory-capture-to-s3"
                    ],
                    "aws:PrincipalArn": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/admin",
                    "kms:ViaService": "lambda.${data.aws_region.current.id}.amazonaws.com"
                }
            }
        },
        {
            "Sid": "encryption-for-loggroups",
            "Effect": "Allow",
            "Principal": {
                "Service": "logs.${data.aws_region.current.id}.amazonaws.com"
            },
            "Action": [
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:Encrypt*",
                "kms:Describe*",
                "kms:Decrypt*"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:EncryptionContext:${data.aws_partition.current.partition}:logs:arn": [
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/stepfunction/tdir",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-format-eventbridge",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-format-eventbridge-input",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-check-snapshots",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-create-streaming-instance",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-check-instance-managed",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-run-command-stream-snapshot-to-s3",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-wait-run-command",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-create-sidecar-volume-instance",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-run-command-stream-sidecar-volume-snapshot-to-ec2",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-prepare-and-attach-volume",
                        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.id}:${data.aws_caller_identity.current.id}:log-group:/aws/lambda/tdir-run-command-stream-memory-capture-to-s3"
                    ],
                    "aws:SourceOrgID": "${data.aws_organizations_organization.current.id}"
                }
            }
        },
        {
            "Sid": "ec2runinstances",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": "kms:GenerateDataKeyWithoutPlaintext",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/tdir-lambda",
                    "kms:ViaService": "ec2.${data.aws_region.current.id}.amazonaws.com"
                }
            }
        },
        {
            "Sid": "ec2ebsdecrypt",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": "kms:CreateGrant",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:GrantConstraintType": "EncryptionContextSubset",
                    "aws:PrincipalArn": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/tdir-lambda",
                    "kms:ViaService": "ec2.${data.aws_region.current.id}.amazonaws.com"
                },
                "StringLike": {
                    "kms:EncryptionContext:${data.aws_partition.current.partition}:ebs:id": "vol-*"
                },
                "ForAllValues:StringEquals": {
                    "kms:GrantOperations": "Decrypt"
                },
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        },
        {
            "Sid": "AllowMacietoDecryptheKey",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": [
                "kms:List*",
                "kms:GetKeyRotationStatus",
                "kms:GetKeyPolicy",
                "kms:Describe*",
                "kms:Decrypt"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/aws-service-role/macie.amazonaws.com/AWSServiceRoleForAmazonMacie"
                }
            }
        },
        {
            "Sid": "s3upload",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": [
                "kms:GenerateDataKey",
                "kms:Decrypt"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/tdir-ec2-collection",
                    "kms:EncryptionContext:${data.aws_partition.current.partition}:s3:arn": "arn:${data.aws_partition.current.partition}:s3:::tdir-${data.aws_caller_identity.current.id}-${data.aws_region.current.id}",
                    "kms:ViaService": "s3.${data.aws_region.current.id}.amazonaws.com"
                }
            }
        },
        {
            "Sid": "s3download",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": "kms:Decrypt",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/admin",
                    "kms:EncryptionContext:${data.aws_partition.current.partition}:s3:arn": "arn:${data.aws_partition.current.partition}:s3:::tdir-${data.aws_caller_identity.current.id}-${data.aws_region.current.id}",
                    "kms:ViaService": "s3.${data.aws_region.current.id}.amazonaws.com"
                }
            }
        },
        {
            "Sid": "AllowConfigandAccessAnalyzertoReadKeyAttributes",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:root"
            },
            "Action": [
                "kms:List*",
                "kms:GetKeyRotationStatus",
                "kms:GetKeyPolicy",
                "kms:Describe*"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": [
                        "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer",
                        "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
                    ]
                }
            }
        },
        {
            "Sid": "DenyNonOrganizationalServiceEncryptionUse",
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
            "Action": "kms:*",
            "Resource": "*",
            "Condition": {
                "StringNotEqualsIfExists": {
                    "aws:SourceOrgID": "${data.aws_organizations_organization.current.id}"
                },
                "Null": {
                    "aws:SourceOrgID": "false"
                },
                "BoolIfExists": {
                    "aws:PrincipalIsAWSService": "true"
                }
            }
        },
        {
            "Sid": "PreventNonOrganizationalAccess",
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
            "Action": "kms:*",
            "Resource": "*",
            "Condition": {
                "StringNotEqualsIfExists": {
                    "aws:PrincipalOrgID": "${data.aws_organizations_organization.current.id}"
                },
                "BoolIfExists": {
                    "aws:PrincipalIsAWSService": "false"
                }
            }
        },
        {
            "Sid": "MaxDeletionWindow",
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
            "Action": "kms:ScheduleKeyDeletion",
            "Resource": "*",
            "Condition": {
                "NumericLessThan": {
                    "kms:ScheduleKeyDeletionPendingWindowInDays": "30"
                }
            }
        },
        {
            "Sid": "PreventSafetyLockoutBypass",
            "Effect": "Deny",
            "Principal": {
                "AWS": "*"
            },
            "Action": "kms:PutKeyPolicy",
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "kms:BypassPolicyLockoutSafetyCheck": "true"
                }
            }
        }
    ]
}
EOF
  enable_key_rotation     = true
}

resource "aws_kms_key" "fail4" {
  description             = "fail4"
  deletion_window_in_days = 30
  policy = templatefile("${path.module}/templates/kms-fail-4.json", {
    "accountid"    = "${data.aws_caller_identity.current.id}",
    "orgid"        = "${data.aws_caller_identity.current.id}",
    "partition"    = "${data.aws_partition.current.partition}",
    "principalarn" = "${data.aws_iam_session_context.current.issuer_arn}",
    "region"       = "${data.aws_iam_session_context.current.issuer_arn}"
  })
  enable_key_rotation = true
}

resource "aws_kms_key" "fail5" {
  description = "fail5"
}

resource "aws_kms_key_policy" "fail5" {
  key_id = aws_kms_key.fail5.id
  policy = jsonencode({
    Id = "fail5"
    Statement = [
      {
        Action = "kms:*"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Resource = "*"
        Sid      = "Enable IAM User Permissions"
      },
    ]
    Version = "2012-10-17"
  })
}

