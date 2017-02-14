# Written by: Andrew Jackson
# This is used to pull repo from github and drop to S3
import urllib2
import boto3
import sys
import json
import cfnresponse
s3 = boto3.resource('s3')

def lambda_handler(event, context):
    print "event.dump = " + json.dumps(event)
    # If nto valid cloudformation custom resource call


    print "test"
    if not event['bucket_name'] or not event['git_url'] or not event['key']:
        cfnresponse.send(event, context, cfnresponse.FAILED, "Bucket Name, Git URL and Key are all required.", '')
        return

    response_status = cfnresponse.SUCCESS
    results = {}

    try:

        for keys,values in event.items():
            if "bucket_name" in keys:
                bucket_name = values
            if "git_url" in keys:
                git_url = values
            if "key" in keys:
                key = values
        response = urllib2.urlopen (git_url.encode('utf-8'))
        zipcontent = response.read()
        s3.Bucket(bucket_name).put_object(Key='(key)', Body='(zipcontent)')
    except Exception as e:
        print # coding=utf-8

    finally:
        cfnresponse.send(event, context, cfnresponse.SUCCESS, 'Completed Success', '')
