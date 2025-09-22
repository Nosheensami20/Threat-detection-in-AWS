Lambda Function
import boto3
import json
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize EC2 client
ec2 = boto3.client('ec2')

# Your target instance ID
TARGET_INSTANCE_ID = "i-<EC2-ID>"  # demo-instance-guardduty

def lambda_handler(event, context):
    """
    Remediation for SSH brute force - stops your real EC2 instance
    """
    try:
        logger.info("=== SSH Brute Force Remediation Started ===")
        logger.info(f"Target instance for remediation: {TARGET_INSTANCE_ID}")
        
        # Extract GuardDuty finding details
        detail = event.get("detail", {})
        finding_type = detail.get("type", "")
        
        logger.info(f"Finding type: {finding_type}")
        
        # Only handle SSH brute force findings
        if finding_type != "UnauthorizedAccess:EC2/SSHBruteForce":
            logger.info(f"Ignoring finding type: {finding_type}")
            return {
                'statusCode': 200,
                'body': json.dumps('Not an SSH brute force finding - no action taken')
            }
        
        # Get severity for logging
        severity = detail.get("severity", 0)
        logger.info(f"Finding severity: {severity}")
        
        # Extract instance ID from finding (for logging purposes)
        resource = detail.get("resource", {})
        instance_details = resource.get("instanceDetails", {})
        finding_instance_id = instance_details.get("instanceId", "")
        
        logger.info(f"Instance ID from finding: {finding_instance_id}")
        logger.info(f"Will remediate target instance: {TARGET_INSTANCE_ID}")
        
        # Remediate the target instance
        result = isolate_and_stop_instance()
        
        logger.info(f"Remediation completed: {result}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'SSH brute force remediation completed',
                'finding_instance_id': finding_instance_id,
                'target_instance_id': TARGET_INSTANCE_ID,
                'severity': severity,
                'action_taken': result
            })
        }
        
    except Exception as e:
        logger.error(f"Error in remediation: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Remediation failed: {str(e)}')
        }

def isolate_and_stop_instance():
    """
    Isolate and stop the target EC2 instance
    """
    try:
        logger.info(f"Starting remediation of instance {TARGET_INSTANCE_ID}")
        
        # First, check if instance exists and get its details
        try:
            instance_response = ec2.describe_instances(InstanceIds=[TARGET_INSTANCE_ID])
            instance = instance_response['Reservations'][0]['Instances'][0]
            vpc_id = instance['VpcId']
            current_state = instance['State']['Name']
            
            logger.info(f"Instance {TARGET_INSTANCE_ID} current state: {current_state}")
            logger.info(f"Instance is in VPC: {vpc_id}")
            
        except Exception as e:
            logger.error(f"Could not find instance {TARGET_INSTANCE_ID}: {str(e)}")
            return f"failed - instance not found: {str(e)}"
        
        # Create isolation security group
        isolation_sg_name = f"isolation-sg-{TARGET_INSTANCE_ID}-{int(datetime.now().timestamp())}"
        
        try:
            sg_response = ec2.create_security_group(
                GroupName=isolation_sg_name,
                Description=f'Isolation SG for {TARGET_INSTANCE_ID} - SSH brute force detected',
                VpcId=vpc_id
            )
            
            isolation_sg_id = sg_response['GroupId']
            logger.info(f"Created isolation security group: {isolation_sg_id}")
            
            # Tag the security group
            ec2.create_tags(
                Resources=[isolation_sg_id],
                Tags=[
                    {'Key': 'Purpose', 'Value': 'GuardDuty-SSH-Isolation'},
                    {'Key': 'Instance', 'Value': TARGET_INSTANCE_ID},
                    {'Key': 'CreatedBy', 'Value': 'Lambda-Remediation'},
                    {'Key': 'CreatedAt', 'Value': datetime.now().isoformat()}
                ]
            )
            
        except Exception as e:
            logger.error(f"Failed to create security group: {str(e)}")
            isolation_sg_id = "failed-to-create"
        
        # Apply isolation security group (if created successfully)
        if isolation_sg_id != "failed-to-create":
            try:
                ec2.modify_instance_attribute(
                    InstanceId=TARGET_INSTANCE_ID,
                    Groups=[isolation_sg_id]
                )
                logger.info(f"Applied isolation security group {isolation_sg_id} to instance")
            except Exception as e:
                logger.error(f"Failed to apply security group: {str(e)}")
        
        # Stop the instance
        if current_state in ['running', 'pending']:
            try:
                logger.info(f"Stopping instance {TARGET_INSTANCE_ID}")
                stop_response = ec2.stop_instances(InstanceIds=[TARGET_INSTANCE_ID])
                logger.info(f"Stop command sent successfully: {stop_response}")
                
                return f"isolated_and_stopped (SG: {isolation_sg_id})"
                
            except Exception as e:
                logger.error(f"Failed to stop instance: {str(e)}")
                return f"isolated_only - stop failed: {str(e)}"
        else:
            logger.info(f"Instance is already {current_state} - no need to stop")
            return f"isolated_only - instance already {current_state} (SG: {isolation_sg_id})"
        
    except Exception as e:
        logger.error(f"Failed to remediate instance {TARGET_INSTANCE_ID}: {str(e)}")
        return f"failed: {str(e)}"