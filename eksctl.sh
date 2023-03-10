#!/bin/bash
########Attatch administrator policy to ec2 role and run the script########
########Attatch administrator policy to ec2 role and run the script########
########Attatch administrator policy to ec2 role and run the script########
########Attatch administrator policy to ec2 role and run the script########
########Attatch administrator policy to ec2 role and run the script########
########Attatch administrator policy to ec2 role and run the script########

#chnage following paramters as per your requirments 
CLUSTER_NAME=my-cluster124
REGION=eu-north-1
EKS_VERSION=1.24
  # make sure you version matches the version on this block, match it on line 168
  # check version on this website https://github.com/kubernetes/autoscaler/releases
KEY_NAME=key_name # this key should be in your ec2 region
# dont need to chnage these values

availabilityZones1a="${REGION}a"
availabilityZones1b="${REGION}b"
availabilityZones1c="${REGION}c"

echo "################### install aws cli ####################"
sleep 5
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -o awscliv2.zip
sudo ./aws/install
echo "################### install aws kubectl ####################"
sleep 5
aws configure set default.region $REGION
aws configure set default.output json
# Install kubectl 1.21, you can chnage version as per your requirments
curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.21.14/2023-01-30/bin/linux/amd64/kubectl
chmod +x ./kubectl
mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin
echo 'export PATH=$PATH:$HOME/bin' >> ~/.bashrc
kubectl version --short --client
# Install eksctl
echo "################### install aws eksctl ####################\n"
sleep 5
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin
eksctl version
# eks install finish
INSTACE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
echo $INSTACE_ID
EC2_IAM_ROLE=$(aws ec2 describe-instances --instance-ids $INSTACE_ID --query 'Reservations[].Instances[].IamInstanceProfile[].Arn' --output text | awk -F/ '{print $NF}')
echo $EC2_IAM_ROLE
# create policy and attatch it to iam role
sudo yum install jq -y
echo "creating and attatching policy"
echo "creating and attatching policy"
echo "creating and attatching policy"
echo "creating and attatching policy"
echo "creating and attatching policy"
sleep 15
policy_name=$REGION-EKS-$CLUSTER_NAME-AmazonEC2FullAccess
policy_arn=$(aws iam list-policies --query "Policies[?PolicyName=='$policy_name'].Arn" --output text)
if [ -n "$policy_arn" ]; then
  echo "Policy $policy_name exists with ARN: $policy_arn"
  POLICY_ARN_AmazonEC2FullAccess=$policy_arn
else
  POLICY_ARN_AmazonEC2FullAccess=$(aws iam create-policy --policy-name $REGION-EKS-$CLUSTER_NAME-AmazonEC2FullAccess --policy-document '{ "Version": "2012-10-17", "Statement": [ { "Sid": "VisualEditor0", "Effect": "Allow", "Action": "autoscaling:*", "Resource": "*", "Condition": { "ForAnyValue:StringEquals": { "aws:RequestedRegion": "$REGION" } } }, { "Sid": "VisualEditor1", "Effect": "Allow", "Action": "cloudwatch:*", "Resource": "*", "Condition": { "ForAnyValue:StringEquals": { "aws:RequestedRegion": "$REGION" } } }, { "Sid": "VisualEditor2", "Effect": "Allow", "Action": "ec2:*", "Resource": "*", "Condition": { "ForAnyValue:StringEquals": { "aws:RequestedRegion": "$REGION" } } }, { "Sid": "VisualEditor3", "Effect": "Allow", "Action": "elasticloadbalancing:*", "Resource": "*", "Condition": { "ForAnyValue:StringEquals": { "aws:RequestedRegion": "$REGION" } } }, { "Sid": "VisualEditor4", "Effect": "Allow", "Action": "elasticloadbalancing:*", "Resource": "*", "Condition": { "ForAnyValue:StringEquals": { "aws:RequestedRegion": "$REGION" } } }, { "Sid": "VisualEditor5", "Effect": "Allow", "Action": "iam:CreateServiceLinkedRole", "Resource": "*", "Condition": { "StringEquals": { "iam:AWSServiceName": [ "autoscaling.amazonaws.com", "ec2scheduled.amazonaws.com", "elasticloadbalancing.amazonaws.com", "spot.amazonaws.com", "spotfleet.amazonaws.com", "transitgateway.amazonaws.com" ] }, "ForAnyValue:StringEquals": { "aws:RequestedRegion": "$REGION" } } } ]}' | jq -r '.[].Arn')
  echo "Policy arn is $POLICY_ARN_AmazonEC2FullAccess "
fi
policy_name=$REGION-EKS-$CLUSTER_NAME-AWSCloudFormationFullAccess 
policy_arn=$(aws iam list-policies --query "Policies[?PolicyName=='$policy_name'].Arn" --output text)
if [ -n "$policy_arn" ]; then
  echo "Policy $policy_name exists with ARN: $policy_arn"
  POLICY_ARN_AWSCloudFormationFullAccess=$policy_arn
else
    POLICY_ARN_AWSCloudFormationFullAccess=$(aws iam create-policy --policy-name $REGION-EKS-$CLUSTER_NAME-AWSCloudFormationFullAccess --policy-document '{"Version":"2012-10-17","Statement":[{"Sid":"VisualEditor0","Effect":"Allow","Action":"cloudformation:*","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:RequestedRegion":"$REGION"}}},{"Sid":"VisualEditor1","Effect":"Allow","Action":"cloudformation:*","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:RequestedRegion":"$REGION"}}}]}' | jq -r '.[].Arn')
    echo $POLICY_ARN_AWSCloudFormationFullAccess
fi
policy_name=$REGION-EKS-$CLUSTER_NAME-EksAllAccess 
policy_arn=$(aws iam list-policies --query "Policies[?PolicyName=='$policy_name'].Arn" --output text)
if [ -n "$policy_arn" ]; then
  echo "Policy $policy_name exists with ARN: $policy_arn"
  POLICY_ARN_EksAllAccess=$policy_arn
else
    POLICY_ARN_EksAllAccess=$(aws iam create-policy --policy-name $REGION-EKS-$CLUSTER_NAME-EksAllAccess --policy-document '{"Version":"2012-10-17","Statement":[{"Sid":"VisualEditor0","Effect":"Allow","Action":"eks:*","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:RequestedRegion":"$REGION"}}},{"Sid":"VisualEditor1","Effect":"Allow","Action":["kms:DescribeKey","kms:CreateGrant"],"Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:RequestedRegion":"$REGION"}}},{"Sid":"VisualEditor2","Effect":"Allow","Action":"logs:PutRetentionPolicy","Resource":"*","Condition":{"ForAnyValue:StringEquals":{"aws:RequestedRegion":"$REGION"}}},{"Sid":"VisualEditor3","Effect":"Allow","Action":["ssm:GetParameters","ssm:GetParameter"],"Resource":["arn:aws:ssm:*:221120016444:parameter/aws/*","arn:aws:ssm:*::parameter/aws/*"],"Condition":{"ForAnyValue:StringEquals":{"aws:RequestedRegion":"$REGION"}}}]}' | jq -r '.[].Arn')
    echo $POLICY_ARN_EksAllAccess
fi
policy_name=$REGION-EKS-$CLUSTER_NAME-IamLimitedAccess
policy_arn=$(aws iam list-policies --query "Policies[?PolicyName=='$policy_name'].Arn" --output text)
if [ -n "$policy_arn" ]; then
  echo "Policy $policy_name exists with ARN: $policy_arn"
  POLICY_ARN_IamLimitedAccess=$policy_arn
else
    POLICY_ARN_IamLimitedAccess=$(aws iam create-policy --policy-name $REGION-EKS-$CLUSTER_NAME-IamLimitedAccess --policy-document '{"Version": "2012-10-17","Statement": [{"Sid": "VisualEditor0","Effect": "Allow","Action": ["iam:CreateInstanceProfile","iam:TagRole","iam:RemoveRoleFromInstanceProfile","iam:DeletePolicy","iam:CreateRole","iam:AttachRolePolicy","iam:PutRolePolicy","iam:AddRoleToInstanceProfile","iam:ListInstanceProfilesForRole","iam:PassRole","iam:DetachRolePolicy","iam:DeleteRolePolicy","iam:ListAttachedRolePolicies","iam:DeleteOpenIDConnectProvider","iam:DeleteInstanceProfile","iam:GetRole","iam:GetInstanceProfile","iam:GetPolicy","iam:DeleteRole","iam:ListInstanceProfiles","iam:CreateOpenIDConnectProvider","iam:CreatePolicy","iam:ListPolicyVersions","iam:GetOpenIDConnectProvider","iam:TagOpenIDConnectProvider","iam:GetRolePolicy"],"Resource": ["arn:aws:iam::221120016444:policy/eksctl-*","arn:aws:iam::221120016444:instance-profile/eksctl-*","arn:aws:iam::221120016444:role/eksctl-*","arn:aws:iam::221120016444:role/aws-service-role/eks-nodegroup.amazonaws.com/AWSServiceRoleForAmazonEKSNodegroup","arn:aws:iam::221120016444:role/eksctl-managed-*","arn:aws:iam::221120016444:oidc-provider/*"],"Condition": {"ForAnyValue:StringEquals": {"aws:RequestedRegion": "$REGION"}}},{"Sid": "VisualEditor1","Effect": "Allow","Action": "iam:GetRole","Resource": "arn:aws:iam::221120016444:role/*","Condition": {"ForAnyValue:StringEquals": {"aws:RequestedRegion": "$REGION"}}},{"Sid": "VisualEditor2","Effect": "Allow","Action": "iam:CreateServiceLinkedRole","Resource": "*","Condition": {"StringEquals": {"iam:AWSServiceName": ["eks.amazonaws.com","eks-nodegroup.amazonaws.com","eks-fargate.amazonaws.com"]},"ForAnyValue:StringEquals": {"aws:RequestedRegion": "$REGION"}}}]}' | jq -r '.[].Arn')
    echo $POLICY_ARN_IamLimitedAccess
fi

#aws ec2 associate-iam-instance-profile --instance-id $INSTACE_ID --iam-instance-profile Name=my-profile
# create plicy and attatch it to eks bastion role
aws iam attach-role-policy --role-name $EC2_IAM_ROLE --policy-arn $POLICY_ARN_AmazonEC2FullAccess
aws iam attach-role-policy --role-name $EC2_IAM_ROLE --policy-arn $POLICY_ARN_AWSCloudFormationFullAccess
aws iam attach-role-policy --role-name $EC2_IAM_ROLE --policy-arn $POLICY_ARN_EksAllAccess
aws iam attach-role-policy --role-name $EC2_IAM_ROLE --policy-arn $POLICY_ARN_IamLimitedAccess

echo "creating Cluster"
sleep 15
# create cluster start
#eksctl create cluster -f - <<EOF
eksctl create cluster -f - <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: $CLUSTER_NAME
  region: $REGION
  version: "$EKS_VERSION"
vpc:
  cidr: 10.10.0.0/16
nodeGroups:
  - name: database
    iam:
      withAddonPolicies:
        autoScaler: true
    labels: { node-env: dev , role: database }
    instanceType: t3.small
    desiredCapacity: 1
    minSize: 1
    maxSize: 5
    #volumeSize: 80
    privateNetworking: true
    ssh: # use existing EC2 key
      publicKeyName: $KEY_NAME
      enableSsm: true
    availabilityZones:
      - $availabilityZones1a
  - name: services 
  # iam policy turn on autoscaling
    iam:
      withAddonPolicies:
        autoScaler: true
  # end of autoscaling
    labels: 
      node-env: dev
      role: spot
    minSize: 2
    maxSize: 5
    instancesDistribution:
      maxPrice: 0.017
      instanceTypes: ["t3.small", "t3.medium"] # At least one instance type should be specified
      onDemandBaseCapacity: 0
      onDemandPercentageAboveBaseCapacity: 50
    ssh: # use existing EC2 key
      publicKeyName: $KEY_NAME
      enableSsm: true
    availabilityZones:
      - $availabilityZones1a
      - $availabilityZones1b
      - $availabilityZones1c
EOF

echo "##########################creating autoscaler########################"
echo "##########################creating autoscaler########################"
echo "##########################creating autoscaler########################"
echo "##########################creating autoscaler########################"
echo "##########################creating autoscaler########################"
echo "##########################creating autoscaler########################"
echo "##########################creating autoscaler########################"
sleep 5
# create autoscaler
# deployDeploy the Cluster Autoscaler
kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml
curl -Lo cluster-autoscaler-autodiscover.yaml https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml
# check version on this website https://github.com/kubernetes/autoscaler/releases
sed -i.bak -e "s|v1.22.2|v$EKS_VERSION.0|" ./cluster-autoscaler-autodiscover.yaml
sed -i.bak -e "s|<YOUR CLUSTER NAME>|$CLUSTER_NAME|" ./cluster-autoscaler-autodiscover.yaml
kubectl apply -f cluster-autoscaler-autodiscover.yaml
kubectl -n kube-system annotate deployment.apps/cluster-autoscaler cluster-autoscaler.kubernetes.io/safe-to-evict="false" --overwrite

echo "#################### create ingress #####################"
sleep 2
echo "#################### create ingress #####################"
sleep 2
echo "#################### create ingress #####################"
sleep 2
echo "#################### create ingress #####################"
oidc_id=$(aws eks describe-cluster --name $CLUSTER_NAME --query "cluster.identity.oidc.issuer" --output text | cut -d '/' -f 5)
oidc=$(aws iam list-open-id-connect-providers | grep $oidc_id | cut -d "/" -f4)
echo $oidc
if [ -n "$oidc" ]; then
    echo "oidc id already present"
    echo $oidc
else
    echo "assiciating oidc id"
    eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve
fi

sleep 15
if [ $REGION == "us-east-1" ] || [ $REGION == "us-east-2" ] || [ $REGION == "us-west-1" ] || [ $REGION == "us-west-2" ] ; then

  curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.4.7/docs/install/iam_policy_us-gov.json
  aws iam create-policy \
    --policy-name $REGION-$CLUSTER_NAME-EKS-AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam_policy_us-gov.json
  echo "us-region"
else
  curl -O https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.4.7/docs/install/iam_policy.json
  aws iam create-policy \
    --policy-name $REGION-$CLUSTER_NAME-EKS-AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam_policy.json
  echo "non us-region"
fi
sleep 15
eksctl create iamserviceaccount \
  --cluster=$CLUSTER_NAME \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --role-name AmazonEKSLoadBalancerControllerRole \
  --attach-policy-arn=arn:aws:iam::221120016444:policy/$REGION-$CLUSTER_NAME-EKS-AWSLoadBalancerControllerIAMPolicy \
  --approve --override-existing-serviceaccounts
sleep 15
kubectl apply \
    --validate=false \
    -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml
sleep 15
curl -Lo v2_4_7_full.yaml https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases/download/v2.4.7/v2_4_7_full.yaml
sed -i.bak -e '561,569d' ./v2_4_7_full.yaml
sed -i.bak -e "s|your-cluster-name|$CLUSTER_NAME|" ./v2_4_7_full.yaml
kubectl apply -f v2_4_7_full.yaml
sleep 15
curl -Lo v2_4_7_ingclass.yaml https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases/download/v2.4.7/v2_4_7_ingclass.yaml
kubectl apply -f v2_4_7_ingclass.yaml

###
# we can enable cloudwatch logs 
#eksctl utils update-cluster-logging --enable-types={SPECIFY-YOUR-LOG-TYPES-HERE (e.g. all)} --region=eu-north-1 --cluster=my-cluster120
# to delete cluster
# eksctl delete cluster --region=$REGION --name=$CLUSTER_NAME

