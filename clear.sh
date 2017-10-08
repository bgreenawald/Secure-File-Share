#!/bin/bash
./manage.py sqlflush | psql -t -U ndxrnxwwzbnpkc df3ont4q5gv759 -h ec2-54-243-185-123.compute-1.amazonaws.com
