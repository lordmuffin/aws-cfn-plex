#!/usr/bin/python
# Written by: Andrew Jackson
# This is used to pull repo from github and drop to S3
import boto3
import git
import os
import shutil
s3 = boto3.resource('s3')

def lambda_handler(event, context):
    print "event.dump = " + json.dumps(event)
    responseData = {}
    # If not valid cloudformation custom resource call
    try:
        git.Git().clone(event["ResourceProperties"]["git_url"])

        DIR_NAME = "tmp/git"
        REMOTE_URL = event["ResourceProperties"]["git_url"]

        if os.path.isdir(DIR_NAME):
            shutil.rmtree(DIR_NAME)

        os.mkdir(DIR_NAME)

        repo = git.Repo.init(DIR_NAME)
        origin = repo.create_remote('origin',REMOTE_URL)
        origin.fetch()
        origin.pull(origin.refs[0].remote_head)

        print "---- DONE ----"

# Foreach Object in the cloned folder, upload to s3 cloned folder.
        for filename in os.listdir('DIR_NAME'):
            buffer+= open(filename, 'rU').read()
            s3.Bucket(event["ResourceProperties"]["bucket_name"]).put_object(Key=filename, Body=buffer)
            cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, ".zip pulled to S3 Bucket!")
    except Exception:
        cfnresponse.send(event, context, cfnresponse.FAILED, responseData, "Bucket Name and Key are all required.")
        print "ERROR"
